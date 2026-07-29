package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/enel1221/GroupBridge/internal/model"
)

func TestSyncAccessGroupVerifiesGitOpsObjectsWithoutIdentityMutation(t *testing.T) {
	var mu sync.Mutex
	var requests []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, recordedRequest{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/kubernetes/login":
			writeJSON(t, w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": "scoped-token", "lease_duration": 3600, "renewable": true}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/internal/ui/mounts/auth/oidc":
			requireToken(t, r)
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"path": "oidc/", "type": "oidc", "accessor": "auth_oidc_123"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/internal/ui/mounts/orgs":
			requireToken(t, r)
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"path": "orgs/", "type": "kv", "options": map[string]string{"version": "2"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/policies/acl/"+managedName("internal/ccmo"):
			requireToken(t, r)
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]string{"policy": editorPolicyCCMO}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/identity/group/name/"+managedName("internal/ccmo"):
			requireToken(t, r)
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{
				"id": "group-id", "name": managedName("internal/ccmo"), "type": "external",
				"policies": []string{managedName("internal/ccmo")},
				"metadata": map[string]string{
					"managed-by": "groupbridge", "groupbridge-rule": "internal-vault",
					"secret-path": "internal/ccmo", "policy-sha256": hashPolicy(editorPolicyCCMO),
				},
				"alias": map[string]string{
					"id": "alias-id", "name": "/Internal/CCMO",
					"mount_accessor": "auth_oidc_123", "canonical_id": "group-id",
				},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/identity/lookup/group":
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{
				"id": "group-id",
				"alias": map[string]string{
					"id": "alias-id", "name": "/Internal/CCMO",
					"mount_accessor": "auth_oidc_123", "canonical_id": "group-id",
				},
			}})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := New("vault", server.URL, Options{
		KubernetesAuthMount: "kubernetes", KubernetesRole: "groupbridge",
		ServiceAccountTokenFile: writeToken(t, "projected-jwt"),
		OIDCMount:               "oidc", KVMount: "orgs",
	}, server.Client())
	result, err := client.SyncAccessGroup(context.Background(), model.AccessSyncRequest{
		RuleName: "internal-vault", SourceGroup: model.Group{ID: "runtime-only", Path: "/Internal/CCMO"},
		SecretPath: "internal/ccmo", AccessProfile: "editor",
		PolicyMode: "verify-only",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.VerifiedPolicy || !result.Converged {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, req := range requests {
		lookupRead := req.Method == http.MethodPost && req.Path == "/v1/identity/lookup/group"
		if strings.HasPrefix(req.Path, "/v1/identity/") && req.Method != http.MethodGet && !lookupRead {
			t.Fatalf("Vault identity mutation attempted: %+v", req)
		}
		if strings.Contains(req.Path, "/data/") || strings.Contains(req.Path, "/metadata/") ||
			strings.Contains(req.Path, "/identity/group/id/") ||
			req.Path == "/v1/sys/auth" || req.Path == "/v1/sys/mounts" {
			t.Fatalf("broad or secret-data endpoint accessed: %+v", req)
		}
	}
}

func TestSyncAccessGroupFailsBeforeIdentityReadWhenPolicyMissingOrMismatched(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "mismatched"}[mismatch], func(t *testing.T) {
			identityReads := 0
			server := runtimeServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				switch {
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/"):
					if mismatch {
						writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]string{"policy": `path "*" { capabilities = ["sudo"] }`}})
					} else {
						http.Error(w, "missing", http.StatusNotFound)
					}
					return true
				case strings.HasPrefix(r.URL.Path, "/v1/identity/"):
					identityReads++
					http.Error(w, "must not be reached", http.StatusInternalServerError)
					return true
				}
				return false
			})
			defer server.Close()
			client := testClient(t, server)
			_, err := client.SyncAccessGroup(context.Background(), accessRequest())
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "policy") {
				t.Fatalf("expected policy error, got %v", err)
			}
			if identityReads != 0 {
				t.Fatalf("identity was read %d times before policy verification", identityReads)
			}
		})
	}
}

func TestSyncAccessGroupRejectsGroupDrift(t *testing.T) {
	tests := map[string]func(*vaultGroup){
		"internal type":  func(g *vaultGroup) { g.Type = "internal" },
		"extra policy":   func(g *vaultGroup) { g.Policies = append(g.Policies, "root") },
		"metadata":       func(g *vaultGroup) { g.Metadata["secret-path"] = "internal/other" },
		"extra metadata": func(g *vaultGroup) { g.Metadata["extra"] = "drift" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			server := runtimeServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/identity/group/name/") {
					group := validGroup()
					mutate(&group)
					writeJSON(t, w, http.StatusOK, map[string]any{"data": group})
					return true
				}
				return false
			})
			defer server.Close()
			if _, err := testClient(t, server).SyncAccessGroup(context.Background(), accessRequest()); err == nil {
				t.Fatal("expected GitOps drift error")
			}
		})
	}
}

func TestSyncAccessGroupRejectsAliasDrift(t *testing.T) {
	for name, mutate := range map[string]func(*vaultGroup, *vaultAlias){
		"group":     func(g *vaultGroup, _ *vaultAlias) { g.ID = "other-group" },
		"name":      func(_ *vaultGroup, a *vaultAlias) { a.Name = "other-role" },
		"accessor":  func(_ *vaultGroup, a *vaultAlias) { a.MountAccessor = "auth_oidc_other" },
		"canonical": func(_ *vaultGroup, a *vaultAlias) { a.CanonicalID = "other-group" },
	} {
		t.Run(name, func(t *testing.T) {
			server := runtimeServer(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/identity/lookup/group" {
					group := vaultGroup{ID: "group-id"}
					alias := vaultAlias{
						ID: "alias-id", Name: "/Internal/CCMO",
						MountAccessor: "auth_oidc_123", CanonicalID: "group-id",
					}
					mutate(&group, &alias)
					writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"id": group.ID, "alias": alias}})
					return true
				}
				return false
			})
			defer server.Close()
			if _, err := testClient(t, server).SyncAccessGroup(context.Background(), accessRequest()); err == nil {
				t.Fatal("expected alias drift error")
			}
		})
	}
}

func TestSyncAccessGroupUsesNestedKeycloakPathForAliasAndDeterministicVaultNames(t *testing.T) {
	const sourcePath = "/Internal/CCMO/J6"
	const secretPath = "internal/ccmo/j6"
	policyName := managedName(secretPath)
	expectedPolicy := policyFor("orgs", secretPath, "editor", false)
	server := runtimeServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/policies/acl/"+policyName:
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]string{"policy": expectedPolicy}})
			return true
		case r.Method == http.MethodGet && r.URL.Path == "/v1/identity/group/name/"+policyName:
			writeJSON(t, w, http.StatusOK, map[string]any{"data": vaultGroup{
				ID: "group-id", Name: policyName, Type: "external", Policies: []string{policyName},
				Metadata: map[string]string{
					"managed-by": "groupbridge", "groupbridge-rule": "internal-vault",
					"secret-path": secretPath, "policy-sha256": hashPolicy(expectedPolicy),
				},
			}})
			return true
		case r.Method == http.MethodPost && r.URL.Path == "/v1/identity/lookup/group":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["alias_name"] != sourcePath || body["alias_mount_accessor"] != "auth_oidc_123" {
				t.Fatalf("unsafe nested alias lookup: %#v", body)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{
				"id": "group-id",
				"alias": vaultAlias{
					ID: "alias-id", Name: sourcePath,
					MountAccessor: "auth_oidc_123", CanonicalID: "group-id",
				},
			}})
			return true
		}
		return false
	})
	defer server.Close()

	result, err := testClient(t, server).SyncAccessGroup(context.Background(), model.AccessSyncRequest{
		RuleName: "internal-vault", SourceGroup: model.Group{ID: "runtime", Path: sourcePath},
		SecretPath: secretPath, AccessProfile: "editor", PolicyMode: "verify-only",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Converged || !result.VerifiedPolicy {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSyncAccessGroupReportsMissingAliasWhenVaultReturnsNoContent(t *testing.T) {
	server := runtimeServer(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/identity/lookup/group" {
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	})
	defer server.Close()

	_, err := testClient(t, server).SyncAccessGroup(context.Background(), accessRequest())
	if err == nil || !strings.Contains(err.Error(), "lacks its exact GitOps-owned Keycloak full-path OIDC group alias") {
		t.Fatalf("expected clean missing-alias drift error, got %v", err)
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Fatalf("missing alias leaked JSON decoder error: %v", err)
	}
}

func TestKubernetesAuthExpiryRelogsWithRotatedProjectedJWTWithoutRenewPermission(t *testing.T) {
	tokenPath := writeToken(t, "jwt-one")
	var mu sync.Mutex
	var loginJWTs []string
	var renewRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			loginJWTs = append(loginJWTs, body["jwt"])
			index := len(loginJWTs)
			mu.Unlock()
			if index == 1 {
				if err := os.WriteFile(tokenPath, []byte("jwt-two"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeJSON(t, w, http.StatusOK, map[string]any{"auth": map[string]any{
				"client_token": "token", "lease_duration": 0,
			}})
		case "/v1/auth/token/renew-self":
			renewRequests++
			http.Error(w, "must not renew", http.StatusForbidden)
		case "/v1/sys/internal/ui/mounts/auth/oidc":
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"path": "oidc/", "type": "jwt", "accessor": "auth_oidc_123"}})
		case "/v1/sys/internal/ui/mounts/orgs":
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"path": "orgs/", "type": "kv", "options": map[string]string{"version": "2"}}})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := New("vault", server.URL, Options{
		KubernetesAuthMount: "kubernetes", KubernetesRole: "groupbridge",
		ServiceAccountTokenFile: tokenPath, OIDCMount: "oidc", KVMount: "orgs",
	}, server.Client())
	if err := client.HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if renewRequests != 0 || len(loginJWTs) < 2 || loginJWTs[0] != "jwt-one" || loginJWTs[1] != "jwt-two" {
		t.Fatalf("projected token rotation not honored: renewals=%d JWTs=%v", renewRequests, loginJWTs)
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	followed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/evil" {
			followed = true
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/evil", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := New("vault", server.URL, Options{
		KubernetesAuthMount: "kubernetes", KubernetesRole: "groupbridge",
		ServiceAccountTokenFile: writeToken(t, "jwt"), OIDCMount: "oidc", KVMount: "orgs",
	}, nil)
	if err := client.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected redirect error")
	}
	if followed {
		t.Fatal("Vault client followed a redirect")
	}
}

func TestDeterministicNameAndUmbrellaPolicyGoldenContract(t *testing.T) {
	const expectedName = "groupbridge-org-internal-ccmo-6c7695c6"
	const expectedPolicySHA256 = "864defdb624f2c521ac39ff8f173b91a4d40ccd6c056a04664ae202fae6d32a8"
	if got := managedName("internal/ccmo"); got != expectedName {
		t.Fatalf("managed name = %q", got)
	}
	if got := managedName("internal/blue_team"); got != "groupbridge-org-internal-blue-team-fbd986f0" {
		t.Fatalf("underscore-safe name = %q", got)
	}
	if got := managedName("internal/" + strings.Repeat("very-long-segment", 8)); len(got) > 63 {
		t.Fatalf("managed name exceeds 63 characters: %d %q", len(got), got)
	}
	if got := hashPolicy(policyFor("orgs", "internal/ccmo", "editor", true)); got != expectedPolicySHA256 {
		t.Fatalf("discoverable editor policy SHA-256 = %q", got)
	}
}

func TestDiscoverablePolicyAddsOnlyListOnlyMetadataAncestors(t *testing.T) {
	got := policyFor("orgs", "internal/ccmo/j6", "viewer", true)
	const prefix = `path "orgs/metadata/" {
  capabilities = ["list"]
}

path "orgs/metadata/internal" {
  capabilities = ["list"]
}

path "orgs/metadata/internal/ccmo" {
  capabilities = ["list"]
}

`
	if !strings.HasPrefix(got, prefix) || strings.Contains(prefix, `path "orgs/data/`) ||
		strings.Contains(prefix, "metadata/internal/*") {
		t.Fatalf("unsafe discoverable policy:\n%s", got)
	}
}

const editorPolicyCCMO = `path "orgs/data/internal/ccmo" {
  capabilities = ["create", "read", "update", "patch", "delete"]
}

path "orgs/data/internal/ccmo/*" {
  capabilities = ["create", "read", "update", "patch", "delete"]
}

path "orgs/metadata/internal/ccmo" {
  capabilities = ["read", "list"]
}

path "orgs/metadata/internal/ccmo/*" {
  capabilities = ["read", "list"]
}
`

type recordedRequest struct {
	Method string
	Path   string
	Body   string
}

func runtimeServer(t *testing.T, custom func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if custom != nil && custom(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/kubernetes/login":
			writeJSON(t, w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": "token", "lease_duration": 3600}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/internal/ui/mounts/auth/oidc":
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"path": "oidc/", "type": "oidc", "accessor": "auth_oidc_123"}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/internal/ui/mounts/orgs":
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"path": "orgs/", "type": "kv", "options": map[string]string{"version": "2"}}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/"):
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]string{"policy": editorPolicyCCMO}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/identity/group/name/"):
			writeJSON(t, w, http.StatusOK, map[string]any{"data": validGroup()})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/identity/lookup/group":
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{
				"id": "group-id",
				"alias": map[string]string{
					"id": "alias-id", "name": "/Internal/CCMO",
					"mount_accessor": "auth_oidc_123", "canonical_id": "group-id",
				},
			}})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
}

func validGroup() vaultGroup {
	return vaultGroup{
		ID: "group-id", Name: managedName("internal/ccmo"), Type: "external",
		Policies: []string{managedName("internal/ccmo")},
		Metadata: map[string]string{
			"managed-by": "groupbridge", "groupbridge-rule": "internal-vault",
			"secret-path": "internal/ccmo", "policy-sha256": hashPolicy(editorPolicyCCMO),
		},
	}
}

func accessRequest() model.AccessSyncRequest {
	return model.AccessSyncRequest{
		RuleName: "internal-vault", SourceGroup: model.Group{ID: "runtime", Path: "/Internal/CCMO"},
		SecretPath:    "internal/ccmo",
		AccessProfile: "editor", PolicyMode: "verify-only",
	}
}

func testClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	return New("vault", server.URL, Options{
		KubernetesAuthMount: "kubernetes", KubernetesRole: "groupbridge",
		ServiceAccountTokenFile: writeToken(t, "jwt"), OIDCMount: "oidc", KVMount: "orgs",
	}, server.Client())
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func requireToken(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("X-Vault-Token") != "scoped-token" {
		t.Fatalf("missing scoped Vault token on %s %s", r.Method, r.URL.Path)
	}
}

func writeToken(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault-token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
