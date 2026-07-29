// Package vault verifies GitOps-owned Vault organization access. Vault Config
// Operator owns policies, external groups, and aliases; GroupBridge is strictly
// read-only and never provisions users or mutates identity/secret state.
package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/enel1221/GroupBridge/internal/model"
)

var errNotFound = errors.New("Vault object not found")

type Options struct {
	KubernetesAuthMount     string
	KubernetesRole          string
	ServiceAccountTokenFile string
	OIDCMount               string
	KVMount                 string
}

type Client struct {
	name       string
	baseURL    string
	options    Options
	httpClient *http.Client

	authMu    sync.Mutex
	token     string
	expiresAt time.Time
}

func New(name, baseURL string, options Options, httpClient *http.Client) *Client {
	var client http.Client
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client = http.Client{Timeout: 20 * time.Second, Transport: transport}
	} else {
		client = *httpClient
		if client.Timeout == 0 {
			client.Timeout = 20 * time.Second
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{name: name, baseURL: strings.TrimRight(baseURL, "/"), options: options, httpClient: &client}
}

func (c *Client) Name() string { return c.name }

func (c *Client) HealthCheck(ctx context.Context) error {
	_, _, err := c.discoverRuntime(ctx)
	return err
}

func (c *Client) SyncAccessGroup(ctx context.Context, req model.AccessSyncRequest) (result model.AccessResult, err error) {
	started := time.Now()
	result.Provider = c.name
	result.SourceGroup = req.SourceGroup.Path
	result.SecretPath = req.SecretPath
	defer func() { result.Duration = time.Since(started) }()

	if req.PolicyMode != "verify-only" {
		return result, fmt.Errorf("Vault policy mode %q is not supported; all Vault access objects must be GitOps-owned", req.PolicyMode)
	}
	accessor, mount, err := c.discoverRuntime(ctx)
	if err != nil {
		return result, err
	}
	policyName := managedName(req.SecretPath)
	expectedPolicy := policyFor(mount, req.SecretPath, req.AccessProfile, req.Discoverable)
	expectedHash := hashPolicy(expectedPolicy)
	if err := c.verifyPolicy(ctx, policyName, expectedPolicy); err != nil {
		return result, err
	}
	result.VerifiedPolicy = true

	group, found, err := c.getGroupByName(ctx, policyName)
	if err != nil {
		return result, err
	}
	if !found {
		return result, fmt.Errorf("required GitOps-owned Vault external group %q is missing", policyName)
	}
	expectedMetadata := map[string]string{
		"managed-by":       "groupbridge",
		"groupbridge-rule": req.RuleName,
		"secret-path":      req.SecretPath,
		"policy-sha256":    expectedHash,
	}
	if err := validateGitOpsGroup(group, policyName, expectedMetadata); err != nil {
		return result, err
	}
	aliasName := req.SourceGroup.Path
	aliasGroup, alias, found, err := c.lookupAlias(ctx, aliasName, accessor)
	if err != nil {
		return result, err
	}
	if !found || aliasGroup.ID != group.ID || alias.ID == "" || alias.Name != aliasName ||
		alias.MountAccessor != accessor || alias.CanonicalID != group.ID {
		return result, fmt.Errorf("Vault external group %q lacks its exact GitOps-owned Keycloak full-path OIDC group alias %q", policyName, aliasName)
	}
	result.Converged = true
	return result, nil
}

type vaultAlias struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	MountAccessor string `json:"mount_accessor"`
	CanonicalID   string `json:"canonical_id"`
}

type vaultGroup struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Policies []string          `json:"policies"`
	Metadata map[string]string `json:"metadata"`
}

func (c *Client) getGroupByName(ctx context.Context, name string) (vaultGroup, bool, error) {
	var response struct {
		Data vaultGroup `json:"data"`
	}
	err := c.request(ctx, http.MethodGet, "identity/group/name/"+url.PathEscape(name), nil, &response)
	if errors.Is(err, errNotFound) {
		return vaultGroup{}, false, nil
	}
	if err != nil {
		return vaultGroup{}, false, fmt.Errorf("read GitOps-owned Vault external group: %w", err)
	}
	return response.Data, true, nil
}

func (c *Client) lookupAlias(ctx context.Context, name, accessor string) (vaultGroup, vaultAlias, bool, error) {
	var response struct {
		Data struct {
			vaultGroup
			Alias vaultAlias `json:"alias"`
		} `json:"data"`
	}
	body := map[string]string{"alias_name": name, "alias_mount_accessor": accessor}
	err := c.request(ctx, http.MethodPost, "identity/lookup/group", body, &response)
	if errors.Is(err, errNotFound) {
		return vaultGroup{}, vaultAlias{}, false, nil
	}
	if err != nil {
		return vaultGroup{}, vaultAlias{}, false, fmt.Errorf("read GitOps-owned Vault group alias: %w", err)
	}
	if response.Data.ID == "" && response.Data.Alias.ID == "" {
		return vaultGroup{}, vaultAlias{}, false, nil
	}
	return response.Data.vaultGroup, response.Data.Alias, true, nil
}

func validateGitOpsGroup(group vaultGroup, expectedName string, expectedMetadata map[string]string) error {
	if group.Name != expectedName || group.Type != "external" {
		return fmt.Errorf("Vault group %q is not the expected GitOps-owned external group", expectedName)
	}
	if len(group.Policies) != 1 || group.Policies[0] != expectedName {
		return fmt.Errorf("Vault group %q does not attach exactly its compiled policy", expectedName)
	}
	if len(group.Metadata) != len(expectedMetadata) {
		return fmt.Errorf("Vault group %q metadata does not exactly match GitOps intent", expectedName)
	}
	for key, expected := range expectedMetadata {
		if group.Metadata[key] != expected {
			return fmt.Errorf("Vault group %q metadata does not exactly match GitOps intent", expectedName)
		}
	}
	return nil
}

func (c *Client) verifyPolicy(ctx context.Context, name, expected string) error {
	var response struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	err := c.request(ctx, http.MethodGet, "sys/policies/acl/"+url.PathEscape(name), nil, &response)
	if errors.Is(err, errNotFound) {
		return fmt.Errorf("required GitOps-owned Vault policy %q is missing", name)
	}
	if err != nil {
		return fmt.Errorf("read GitOps-owned Vault policy %q: %w", name, err)
	}
	if response.Data.Policy != expected {
		return fmt.Errorf("GitOps-owned Vault policy %q does not match the expected least-privilege policy", name)
	}
	return nil
}

func policyFor(mount, secretPath, profile string, discoverable bool) string {
	dataCapabilities := `["read"]`
	if profile == "editor" {
		dataCapabilities = `["create", "read", "update", "patch", "delete"]`
	}
	var navigation strings.Builder
	if discoverable {
		fmt.Fprintf(&navigation, "path %q {\n  capabilities = [\"list\"]\n}\n\n", mount+"/metadata/")
		segments := strings.Split(secretPath, "/")
		for index := 1; index < len(segments); index++ {
			ancestor := strings.Join(segments[:index], "/")
			fmt.Fprintf(&navigation, "path %q {\n  capabilities = [\"list\"]\n}\n\n", mount+"/metadata/"+ancestor)
		}
	}
	return navigation.String() + fmt.Sprintf(`path %q {
  capabilities = %s
}

path %q {
  capabilities = %s
}

path %q {
  capabilities = ["read", "list"]
}

path %q {
  capabilities = ["read", "list"]
}
`, mount+"/data/"+secretPath, dataCapabilities,
		mount+"/data/"+secretPath+"/*", dataCapabilities,
		mount+"/metadata/"+secretPath,
		mount+"/metadata/"+secretPath+"/*")
}

func managedName(secretPath string) string {
	slug := strings.NewReplacer("/", "-", "_", "-").Replace(secretPath)
	sum := sha256.Sum256([]byte(secretPath))
	suffix := hex.EncodeToString(sum[:4])
	const maxSlug = 38
	if len(slug) > maxSlug {
		slug = strings.Trim(slug[:maxSlug], "-_")
	}
	return "groupbridge-org-" + slug + "-" + suffix
}

func hashPolicy(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])
}

func (c *Client) discoverRuntime(ctx context.Context) (string, string, error) {
	type mountInfo struct {
		Accessor string            `json:"accessor"`
		Path     string            `json:"path"`
		Type     string            `json:"type"`
		Options  map[string]string `json:"options"`
	}
	var authResponse struct {
		Data mountInfo `json:"data"`
	}
	oidcName := strings.Trim(c.options.OIDCMount, "/")
	if err := c.request(ctx, http.MethodGet, "sys/internal/ui/mounts/auth/"+url.PathEscape(oidcName), nil, &authResponse); err != nil {
		return "", "", fmt.Errorf("discover configured Vault OIDC mount: %w", err)
	}
	if authResponse.Data.Accessor == "" || authResponse.Data.Path != oidcName+"/" ||
		(authResponse.Data.Type != "oidc" && authResponse.Data.Type != "jwt") {
		return "", "", fmt.Errorf("configured Vault OIDC mount %q does not exist", c.options.OIDCMount)
	}
	var mountResponse struct {
		Data mountInfo `json:"data"`
	}
	mountName := strings.Trim(c.options.KVMount, "/")
	if err := c.request(ctx, http.MethodGet, "sys/internal/ui/mounts/"+url.PathEscape(mountName), nil, &mountResponse); err != nil {
		return "", "", fmt.Errorf("discover configured Vault secret mount: %w", err)
	}
	if mountResponse.Data.Path != mountName+"/" || mountResponse.Data.Type != "kv" ||
		mountResponse.Data.Options["version"] != "2" {
		return "", "", fmt.Errorf("configured Vault mount %q must be an existing KV v2 mount", mountName)
	}
	return authResponse.Data.Accessor, mountName, nil
}

func (c *Client) request(ctx context.Context, method, path string, requestBody any, responseBody any) error {
	token, err := c.ensureToken(ctx)
	if err != nil {
		return err
	}
	status, err := c.rawRequest(ctx, method, path, requestBody, responseBody, token)
	if err != nil {
		return err
	}
	if status == http.StatusForbidden {
		c.clearToken(token)
		token, err = c.ensureToken(ctx)
		if err != nil {
			return err
		}
		status, err = c.rawRequest(ctx, method, path, requestBody, responseBody, token)
		if err != nil {
			return err
		}
	}
	if status == http.StatusNotFound {
		return errNotFound
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("Vault API %s %s returned HTTP %d", method, path, status)
	}
	return nil
}

func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.token == "" {
		if err := c.loginLocked(ctx); err != nil {
			return "", err
		}
		return c.token, nil
	}
	if time.Until(c.expiresAt) > 30*time.Second {
		return c.token, nil
	}
	c.token = ""
	if err := c.loginLocked(ctx); err != nil {
		return "", err
	}
	return c.token, nil
}

func (c *Client) clearToken(token string) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

func (c *Client) loginLocked(ctx context.Context) error {
	jwt, err := os.ReadFile(c.options.ServiceAccountTokenFile)
	if err != nil {
		return fmt.Errorf("read projected Vault service-account token: %w", err)
	}
	if len(jwt) == 0 || len(jwt) > 1<<20 || strings.TrimSpace(string(jwt)) == "" {
		return errors.New("projected Vault service-account token is empty or too large")
	}
	var response struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	status, err := c.rawRequest(ctx, http.MethodPost,
		"auth/"+strings.Trim(c.options.KubernetesAuthMount, "/")+"/login",
		map[string]string{"role": c.options.KubernetesRole, "jwt": strings.TrimSpace(string(jwt))}, &response, "")
	if err != nil {
		return fmt.Errorf("authenticate to Vault with Kubernetes auth: %w", err)
	}
	if status < 200 || status >= 300 || response.Auth.ClientToken == "" {
		return fmt.Errorf("Vault Kubernetes login returned HTTP %d without a usable token", status)
	}
	c.token = response.Auth.ClientToken
	c.expiresAt = time.Now().Add(time.Duration(response.Auth.LeaseDuration) * time.Second)
	return nil
}

func (c *Client) rawRequest(ctx context.Context, method, path string, requestBody any, responseBody any, token string) (int, error) {
	var body io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return 0, fmt.Errorf("encode Vault request: %w", err)
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/v1/"+strings.TrimLeft(path, "/"), body)
	if err != nil {
		return 0, fmt.Errorf("build Vault request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("call Vault API: %w", err)
	}
	defer resp.Body.Close()
	if responseBody != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.StatusCode != http.StatusNoContent {
		limited := io.LimitReader(resp.Body, 2<<20)
		if err := json.NewDecoder(limited).Decode(responseBody); err != nil {
			return resp.StatusCode, fmt.Errorf("decode Vault API response: %w", err)
		}
	}
	return resp.StatusCode, nil
}
