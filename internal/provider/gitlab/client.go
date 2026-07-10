// Package gitlab implements GitLab group provisioning and direct membership sync.
package gitlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/state"
)

const (
	apiPageSize = 100
	ownerLevel  = 50
)

var accessLevels = map[string]int{
	"guest": 10, "planner": 15, "reporter": 20, "developer": 30, "maintainer": 40,
}

type Client struct {
	name          string
	baseURL       string
	token         string
	resolverToken string
	oidcProvider  string
	ownershipKey  string
	httpClient    *http.Client
	state         *state.Store

	identityMu sync.Mutex
	identityID int
}

func New(name, baseURL, token, resolverToken, oidcProvider string, httpClient *http.Client, stateStore *state.Store) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		name: name, baseURL: strings.TrimRight(baseURL, "/"), token: token,
		resolverToken: resolverToken, oidcProvider: oidcProvider, ownershipKey: ownershipKey(name, baseURL),
		httpClient: httpClient, state: stateStore,
	}
}

func (c *Client) Name() string { return c.name }

func (c *Client) HealthCheck(ctx context.Context) error {
	_, err := c.currentIdentity(ctx)
	return err
}

type group struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	FullPath string `json:"full_path"`
}

type member struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	AccessLevel  int    `json:"access_level"`
	MemberRoleID *int   `json:"member_role_id"`
}

type user struct {
	ID         int        `json:"id"`
	Username   string     `json:"username"`
	Email      string     `json:"email"`
	State      string     `json:"state"`
	Identities []identity `json:"identities"`
}

type identity struct {
	Provider  string `json:"provider"`
	ExternUID string `json:"extern_uid"`
}

func (c *Client) SyncGroup(ctx context.Context, req model.SyncRequest) (result model.Result, err error) {
	started := time.Now()
	result.Provider = c.name
	result.SourceGroup = req.SourceGroup.Path
	result.TargetGroup = req.TargetPath
	defer func() { result.Duration = time.Since(started) }()

	target, created, err := c.ensureGroup(ctx, req.TargetPath, req.TargetParent, req.CreateGroup)
	if err != nil {
		return result, err
	}
	result.CreatedGroup = created
	mapping, mapped := c.state.Group(c.ownershipKey, req.RuleName, req.SourceGroup.ID)
	if mapped && (mapping.TargetGroupID != strconv.Itoa(target.ID) || mapping.TargetGroupPath != target.FullPath) {
		return result, fmt.Errorf("source group %q was previously bound to GitLab group %q (%s); refusing retarget to %q (%d)", req.SourceGroup.ID, mapping.TargetGroupPath, mapping.TargetGroupID, target.FullPath, target.ID)
	}
	if !mapped {
		mapping = state.GroupMapping{
			Provider: c.ownershipKey, Rule: req.RuleName,
			SourceGroupID: req.SourceGroup.ID, SourceGroupPath: req.SourceGroup.Path,
			TargetGroupID: strconv.Itoa(target.ID), TargetGroupPath: target.FullPath,
			Owned: created || req.AdoptExistingGroup,
		}
	} else if req.AdoptExistingGroup && !mapping.Owned {
		mapping.Owned = true
	}
	mapping.SourceGroupPath = req.SourceGroup.Path
	if req.Prune == "authoritative" && !mapping.Owned {
		return result, fmt.Errorf("authoritative prune requires a GroupBridge-created group or adoptExistingGroup=true for %q", target.FullPath)
	}
	if err := c.state.PutGroup(mapping); err != nil {
		return result, fmt.Errorf("record source-to-target group mapping: %w", err)
	}
	members, err := c.listMembers(ctx, target.ID)
	if err != nil {
		return result, fmt.Errorf("list direct GitLab members for %q: %w", target.FullPath, err)
	}
	existing := make(map[int]member, len(members))
	for _, m := range members {
		existing[m.ID] = m
	}
	desired := make(map[int]user, len(req.SourceGroup.Members))
	for _, sourceUser := range req.SourceGroup.Members {
		targetUser, found, findErr := c.findUser(ctx, sourceUser, req.IdentityMatch)
		if findErr != nil {
			return result, fmt.Errorf("resolve a GitLab user for source group %q: %w", req.SourceGroup.Path, findErr)
		}
		if !found || targetUser.State != "active" {
			result.Unresolved++
			continue
		}
		desired[targetUser.ID] = targetUser
	}
	level := accessLevels[req.AccessLevel]
	for id, targetUser := range desired {
		if err := c.state.ResetAbsent(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(id)); err != nil {
			return result, fmt.Errorf("reset GitLab membership absence observation: %w", err)
		}
		current, exists := existing[id]
		if !exists {
			if err := c.addMember(ctx, target.ID, id, level); err != nil {
				return result, fmt.Errorf("add GitLab member %q to %q: %w", targetUser.Username, target.FullPath, err)
			}
			verified, verifyErr := c.getMember(ctx, target.ID, id)
			if verifyErr != nil {
				return result, fmt.Errorf("verify GitLab member %q after add: %w", targetUser.Username, verifyErr)
			}
			if verified == nil || verified.AccessLevel < level {
				return result, fmt.Errorf("verify GitLab member %q after add: membership is not active at the requested level", targetUser.Username)
			}
			if err := c.state.MarkManaged(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(id)); err != nil {
				return result, fmt.Errorf("record managed GitLab membership: %w", err)
			}
			result.Added++
			continue
		}
		// Updating without member_role_id can silently discard a GitLab custom
		// member role. GroupBridge does not own that field, so preserve it.
		if current.MemberRoleID != nil {
			if current.AccessLevel < level || (req.EnforceAccessLevel && current.AccessLevel != level) {
				return result, fmt.Errorf("GitLab member %q has a custom role that GroupBridge cannot safely change", current.Username)
			}
			continue
		}
		if current.AccessLevel < level || (req.EnforceAccessLevel && current.AccessLevel != level && current.AccessLevel < ownerLevel) {
			if req.Prune == "managed-only" && !c.state.IsManaged(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(id)) {
				return result, fmt.Errorf("GitLab member %q predates GroupBridge; refusing to change unowned access under managed-only prune", current.Username)
			}
			if err := c.updateMember(ctx, target.ID, id, level); err != nil {
				return result, fmt.Errorf("update GitLab member %q in %q: %w", targetUser.Username, target.FullPath, err)
			}
			verified, verifyErr := c.getMember(ctx, target.ID, id)
			if verifyErr != nil {
				return result, fmt.Errorf("verify GitLab member %q after update: %w", targetUser.Username, verifyErr)
			}
			if verified == nil || verified.AccessLevel != level {
				return result, fmt.Errorf("verify GitLab member %q after update: requested level is not active", targetUser.Username)
			}
			result.Updated++
		}
	}
	if result.Unresolved > 0 {
		return result, nil
	}

	selfID, err := c.currentIdentity(ctx)
	if err != nil {
		return result, err
	}
	protected := make(map[string]struct{}, len(req.ProtectedUsers))
	for _, username := range req.ProtectedUsers {
		protected[strings.ToLower(username)] = struct{}{}
	}
	var removals []member
	pendingRemoval := false
	for _, current := range members {
		if _, wanted := desired[current.ID]; wanted {
			continue
		}
		if current.ID == selfID || current.AccessLevel >= ownerLevel || current.MemberRoleID != nil {
			result.SkippedRemoval++
			continue
		}
		if _, ok := protected[strings.ToLower(current.Username)]; ok {
			result.SkippedRemoval++
			continue
		}
		managed := c.state.IsManaged(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(current.ID))
		if req.Prune == "authoritative" || (req.Prune == "managed-only" && managed) {
			confirmed, confirmErr := c.state.ConfirmAbsent(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(current.ID))
			if confirmErr != nil {
				return result, fmt.Errorf("confirm absent GitLab membership: %w", confirmErr)
			}
			if !confirmed {
				result.SkippedRemoval++
				pendingRemoval = true
				continue
			}
			removals = append(removals, current)
		}
	}
	if len(removals) > req.MaxRemovals {
		return result, fmt.Errorf("refusing %d removals from %q: maxRemovals is %d", len(removals), target.FullPath, req.MaxRemovals)
	}
	for _, current := range removals {
		if err := c.removeMember(ctx, target.ID, current.ID); err != nil {
			return result, fmt.Errorf("remove GitLab member %q from %q: %w", current.Username, target.FullPath, err)
		}
		if err := c.state.Unmark(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(current.ID)); err != nil {
			return result, fmt.Errorf("update managed GitLab membership state: %w", err)
		}
		if err := c.state.ResetAbsent(c.ownershipKey, strconv.Itoa(target.ID), strconv.Itoa(current.ID)); err != nil {
			return result, fmt.Errorf("clear GitLab membership absence observation: %w", err)
		}
		result.Removed++
	}
	result.Converged = !pendingRemoval
	return result, nil
}

func (c *Client) ensureGroup(ctx context.Context, fullPath, parentPath string, create bool) (group, bool, error) {
	fullPath = strings.Trim(fullPath, "/")
	parentPath = strings.Trim(parentPath, "/")
	if fullPath == "" {
		return group{}, false, errors.New("target group path is empty")
	}
	if parentPath != "" && fullPath != parentPath && !strings.HasPrefix(fullPath, parentPath+"/") {
		return group{}, false, fmt.Errorf("target path %q is not below configured parent %q", fullPath, parentPath)
	}
	if found, err := c.getGroup(ctx, fullPath); err != nil {
		return group{}, false, err
	} else if found != nil {
		return *found, false, nil
	}
	if !create {
		return group{}, false, fmt.Errorf("GitLab group %q does not exist and createGroups is false", fullPath)
	}

	var current *group
	createdAny := false
	remaining := strings.Split(fullPath, "/")
	start := 0
	if parentPath != "" {
		parent, err := c.getGroup(ctx, parentPath)
		if err != nil {
			return group{}, false, err
		}
		if parent == nil {
			return group{}, false, fmt.Errorf("configured GitLab parent group %q does not exist", parentPath)
		}
		current = parent
		start = len(strings.Split(parentPath, "/"))
	}
	for i := start; i < len(remaining); i++ {
		candidatePath := strings.Join(remaining[:i+1], "/")
		found, err := c.getGroup(ctx, candidatePath)
		if err != nil {
			return group{}, false, err
		}
		if found != nil {
			current = found
			continue
		}
		created, err := c.createGroup(ctx, remaining[i], current)
		if err != nil {
			return group{}, false, fmt.Errorf("create GitLab group %q: %w", candidatePath, err)
		}
		current = &created
		createdAny = true
	}
	if current == nil {
		return group{}, false, fmt.Errorf("could not resolve GitLab group %q", fullPath)
	}
	return *current, createdAny, nil
}

func (c *Client) getGroup(ctx context.Context, fullPath string) (*group, error) {
	var result group
	status, _, err := c.request(ctx, http.MethodGet, "/api/v4/groups/"+url.PathEscape(fullPath), nil, nil, &result)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GitLab groups API returned %s", http.StatusText(status))
	}
	return &result, nil
}

func (c *Client) createGroup(ctx context.Context, segment string, parent *group) (group, error) {
	payload := map[string]any{"name": segment, "path": segment, "visibility": "private"}
	if parent != nil {
		payload["parent_id"] = parent.ID
	}
	var result group
	status, _, err := c.request(ctx, http.MethodPost, "/api/v4/groups", nil, payload, &result)
	if err != nil {
		return group{}, err
	}
	if status < 200 || status >= 300 {
		return group{}, fmt.Errorf("GitLab groups API returned %s", http.StatusText(status))
	}
	return result, nil
}

func (c *Client) listMembers(ctx context.Context, groupID int) ([]member, error) {
	var all []member
	for page := 1; ; page++ {
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(apiPageSize)}}
		var batch []member
		status, headers, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/v4/groups/%d/members", groupID), query, nil, &batch)
		if err != nil {
			return nil, err
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("GitLab group members API returned %s", http.StatusText(status))
		}
		all = append(all, batch...)
		if headers.Get("X-Next-Page") == "" {
			return all, nil
		}
	}
}

func (c *Client) findUser(ctx context.Context, source model.User, match []string) (user, bool, error) {
	for _, field := range match {
		var query url.Values
		switch field {
		case "oidc":
			if source.ID == "" || c.oidcProvider == "" {
				continue
			}
			query = url.Values{"extern_uid": {source.ID}, "provider": {c.oidcProvider}}
		case "username":
			if source.Username == "" {
				continue
			}
			query = url.Values{"username": {source.Username}}
		case "email":
			if source.Email == "" {
				continue
			}
			query = url.Values{"search": {source.Email}}
		default:
			continue
		}
		query.Set("per_page", strconv.Itoa(apiPageSize))
		var users []user
		status, _, err := c.requestWithToken(ctx, c.resolverToken, http.MethodGet, "/api/v4/users", query, nil, &users)
		if err != nil {
			return user{}, false, err
		}
		if status < 200 || status >= 300 {
			return user{}, false, fmt.Errorf("GitLab users API returned %s", http.StatusText(status))
		}
		var matches []user
		for _, candidate := range users {
			if (field == "oidc" && hasIdentity(candidate, c.oidcProvider, source.ID)) ||
				(field == "username" && strings.EqualFold(candidate.Username, source.Username)) ||
				(field == "email" && strings.EqualFold(candidate.Email, source.Email)) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) > 1 {
			return user{}, false, fmt.Errorf("GitLab returned %d exact %s identity matches", len(matches), field)
		}
		if len(matches) == 1 {
			return matches[0], true, nil
		}
	}
	return user{}, false, nil
}

func (c *Client) addMember(ctx context.Context, groupID, userID, level int) error {
	payload := map[string]int{"user_id": userID, "access_level": level}
	status, _, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/v4/groups/%d/members", groupID), nil, payload, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("GitLab group members API returned %s", http.StatusText(status))
	}
	return nil
}

func (c *Client) getMember(ctx context.Context, groupID, userID int) (*member, error) {
	var result member
	status, _, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/v4/groups/%d/members/%d", groupID, userID), nil, nil, &result)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GitLab group member API returned %s", http.StatusText(status))
	}
	return &result, nil
}

func (c *Client) updateMember(ctx context.Context, groupID, userID, level int) error {
	payload := map[string]int{"access_level": level}
	status, _, err := c.request(ctx, http.MethodPut, fmt.Sprintf("/api/v4/groups/%d/members/%d", groupID, userID), nil, payload, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("GitLab group members API returned %s", http.StatusText(status))
	}
	return nil
}

func (c *Client) removeMember(ctx context.Context, groupID, userID int) error {
	query := url.Values{"skip_subresources": {"true"}, "unassign_issuables": {"false"}}
	status, _, err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/v4/groups/%d/members/%d", groupID, userID), query, nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNotFound && (status < 200 || status >= 300) {
		return fmt.Errorf("GitLab group members API returned %s", http.StatusText(status))
	}
	return nil
}

func (c *Client) currentIdentity(ctx context.Context) (int, error) {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()
	if c.identityID != 0 {
		return c.identityID, nil
	}
	var current user
	status, _, err := c.request(ctx, http.MethodGet, "/api/v4/user", nil, nil, &current)
	if err != nil {
		return 0, err
	}
	if status < 200 || status >= 300 || current.ID == 0 {
		return 0, fmt.Errorf("GitLab current-user API returned %s", http.StatusText(status))
	}
	c.identityID = current.ID
	return current.ID, nil
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, payload, dst any) (int, http.Header, error) {
	return c.requestWithToken(ctx, c.token, method, path, query, payload, dst)
}

func (c *Client) requestWithToken(ctx context.Context, token, method, path string, query url.Values, payload, dst any) (int, http.Header, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, fmt.Errorf("encode GitLab request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, nil, fmt.Errorf("build GitLab request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GroupBridge/1")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("call GitLab: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return resp.StatusCode, resp.Header, nil
	}
	if dst != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(dst); err != nil {
			return 0, nil, fmt.Errorf("decode GitLab response: %w", err)
		}
	} else {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<20))
	}
	return resp.StatusCode, resp.Header, nil
}

func hasIdentity(candidate user, provider, externUID string) bool {
	for _, id := range candidate.Identities {
		if id.Provider == provider && id.ExternUID == externUID {
			return true
		}
	}
	return false
}

func ownershipKey(name, baseURL string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(strings.ToLower(baseURL), "/")))
	return fmt.Sprintf("%s@%x", name, sum[:8])
}
