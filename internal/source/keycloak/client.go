// Package keycloak reads current groups and memberships through the Admin REST API.
package keycloak

import (
	"bytes"
	"context"
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
)

const pageSize = 100

type Client struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func New(baseURL, realm, clientID, clientSecret string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"), realm: realm,
		clientID: clientID, clientSecret: clientSecret, httpClient: httpClient,
	}
}

type groupRepresentation struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Path          string                `json:"path"`
	SubGroupCount int                   `json:"subGroupCount"`
	SubGroups     []groupRepresentation `json:"subGroups"`
}

type userRepresentation struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}

func (c *Client) ListGroups(ctx context.Context) ([]model.Group, error) {
	rootPath := fmt.Sprintf("/admin/realms/%s/groups", url.PathEscape(c.realm))
	roots, err := c.listGroupsPage(ctx, rootPath)
	if err != nil {
		return nil, fmt.Errorf("list root groups: %w", err)
	}
	groups := make([]model.Group, 0, len(roots))
	seen := make(map[string]struct{})
	for _, root := range roots {
		if err := c.collectGroup(ctx, root, "", seen, &groups); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

func (c *Client) collectGroup(ctx context.Context, group groupRepresentation, parentPath string, seen map[string]struct{}, groups *[]model.Group) error {
	if group.ID == "" || group.Name == "" {
		return errors.New("keycloak returned a group without an id or name")
	}
	if _, ok := seen[group.ID]; ok {
		return nil
	}
	seen[group.ID] = struct{}{}
	path := group.Path
	if path == "" {
		path = strings.TrimRight(parentPath, "/") + "/" + group.Name
	}
	members, err := c.listMembers(ctx, group.ID)
	if err != nil {
		return fmt.Errorf("list members for group %q: %w", path, err)
	}
	*groups = append(*groups, model.Group{ID: group.ID, Name: group.Name, Path: path, Members: members})

	// Always page the children endpoint. Embedded subGroups can be omitted or
	// truncated depending on Keycloak version and representation settings.
	childPath := fmt.Sprintf("/admin/realms/%s/groups/%s/children", url.PathEscape(c.realm), url.PathEscape(group.ID))
	children, err := c.listGroupsPage(ctx, childPath)
	if err != nil {
		return fmt.Errorf("list child groups for %q: %w", path, err)
	}
	for _, child := range children {
		if err := c.collectGroup(ctx, child, path, seen, groups); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) listGroupsPage(ctx context.Context, path string) ([]groupRepresentation, error) {
	var all []groupRepresentation
	seen := make(map[string]struct{})
	for first := 0; ; {
		query := url.Values{
			"briefRepresentation": {"true"},
			"first":               {strconv.Itoa(first)},
			"max":                 {strconv.Itoa(pageSize)},
		}
		var page []groupRepresentation
		if err := c.get(ctx, path, query, &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return all, nil
		}
		for _, g := range page {
			if _, duplicate := seen[g.ID]; duplicate {
				return nil, errors.New("Keycloak group pagination returned a duplicate id")
			}
			seen[g.ID] = struct{}{}
		}
		all = append(all, page...)
		first += len(page)
	}
}

func (c *Client) listMembers(ctx context.Context, groupID string) ([]model.User, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/members", url.PathEscape(c.realm), url.PathEscape(groupID))
	var result []model.User
	seen := make(map[string]struct{})
	for first := 0; ; {
		query := url.Values{
			"briefRepresentation": {"true"},
			"first":               {strconv.Itoa(first)},
			"max":                 {strconv.Itoa(pageSize)},
		}
		var page []userRepresentation
		if err := c.get(ctx, path, query, &page); err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return result, nil
		}
		for _, user := range page {
			if _, duplicate := seen[user.ID]; duplicate {
				return nil, errors.New("Keycloak member pagination returned a duplicate id")
			}
			seen[user.ID] = struct{}{}
			if user.Enabled {
				result = append(result, model.User{ID: user.ID, Username: user.Username, Email: user.Email})
			}
		}
		first += len(page)
	}
}

func (c *Client) get(ctx context.Context, path string, query url.Values, dst any) error {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.token(ctx)
		if err != nil {
			return err
		}
		u := c.baseURL + path
		if len(query) > 0 {
			u += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return fmt.Errorf("build Keycloak request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "GroupBridge/1")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("call Keycloak: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			c.invalidateToken()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			return fmt.Errorf("Keycloak API returned %s", resp.Status)
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(dst)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("decode Keycloak response: %w", err)
		}
		return nil
	}
	return errors.New("Keycloak authentication failed")
}

func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Now().Add(30*time.Second).Before(c.tokenExpiry) {
		return c.accessToken, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	u := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, url.PathEscape(c.realm))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build Keycloak token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request Keycloak token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return "", fmt.Errorf("Keycloak token endpoint returned %s", resp.Status)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode Keycloak token: %w", err)
	}
	if payload.AccessToken == "" {
		return "", errors.New("Keycloak returned an empty access token")
	}
	c.accessToken = payload.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	return c.accessToken, nil
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.accessToken = ""
	c.tokenExpiry = time.Time{}
	c.mu.Unlock()
}
