package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/enel1221/GroupBridge/internal/credential"
	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/state"
)

func TestSyncGroupAddsDesiredAndProtectsOwner(t *testing.T) {
	var mu sync.Mutex
	added := 0
	removed := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(user{ID: 99, Username: "sync-bot", State: "active"})
	})
	mux.HandleFunc("/api/v4/groups/platform%2Fdevelopers", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(group{ID: 7, FullPath: "platform/developers"})
	})
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("username") == "alice" {
			json.NewEncoder(w).Encode([]user{{ID: 1, Username: "alice", Email: "alice@example.test", State: "active"}})
			return
		}
		json.NewEncoder(w).Encode([]user{})
	})
	mux.HandleFunc("/api/v4/groups/7/members", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			added++
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			return
		}
		json.NewEncoder(w).Encode([]member{
			{ID: 50, Username: "root", AccessLevel: ownerLevel},
			{ID: 99, Username: "sync-bot", AccessLevel: 40},
			{ID: 2, Username: "stale", AccessLevel: 30},
		})
	})
	mux.HandleFunc("/api/v4/groups/7/members/2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.Query().Get("skip_subresources") != "true" || r.URL.Query().Get("unassign_issuables") != "false" {
			t.Fatalf("unsafe delete query: %s", r.URL.RawQuery)
		}
		mu.Lock()
		removed++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/v4/groups/7/members/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("verification method = %s", r.Method)
		}
		json.NewEncoder(w).Encode(member{ID: 1, Username: "alice", AccessLevel: 30})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := New("gitlab", srv.URL, "token", "resolver", "openid_connect", srv.Client(), store)
	if _, err := store.ConfirmAbsent(c.ownershipKey, "7", "2"); err != nil {
		t.Fatal(err)
	}

	result, err := c.SyncGroup(context.Background(), model.SyncRequest{
		SourceGroup: model.Group{ID: "developers", Path: "/developers", Members: []model.User{{Username: "alice", Email: "alice@example.test"}}},
		TargetPath:  "platform/developers", TargetParent: "platform", AccessLevel: "developer", RuleName: "teams",
		AdoptExistingGroup: true, Prune: "authoritative", MaxRemovals: 5, IdentityMatch: []string{"username", "email"},
	})
	if err != nil {
		t.Fatalf("SyncGroup() error = %v", err)
	}
	if result.Added != 1 || result.Removed != 1 || result.SkippedRemoval != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if added != 1 || removed != 1 {
		t.Fatalf("added=%d removed=%d", added, removed)
	}
}

func TestSyncGroupHonorsRemovalLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(user{ID: 99}) })
	mux.HandleFunc("/api/v4/groups/team", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(group{ID: 7, FullPath: "team"})
	})
	mux.HandleFunc("/api/v4/groups/7/members", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]member{{ID: 1, Username: "a", AccessLevel: 30}, {ID: 2, Username: "b", AccessLevel: 30}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store, _ := state.Open(filepath.Join(t.TempDir(), "state.json"))
	c := New("gitlab", srv.URL, "token", "resolver", "openid_connect", srv.Client(), store)
	for _, id := range []string{"1", "2"} {
		if _, err := store.ConfirmAbsent(c.ownershipKey, "7", id); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.SyncGroup(context.Background(), model.SyncRequest{
		SourceGroup: model.Group{ID: "team", Path: "/team"}, TargetPath: "team", AccessLevel: "developer", RuleName: "teams",
		AdoptExistingGroup: true, Prune: "authoritative", MaxRemovals: 1, IdentityMatch: []string{"username"},
	})
	if err == nil {
		t.Fatal("expected max-removals error")
	}
}

func TestSyncGroupUnresolvedIdentitySkipsAllPruning(t *testing.T) {
	deleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/groups/team", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(group{ID: 7, FullPath: "team"})
	})
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode([]user{}) })
	mux.HandleFunc("/api/v4/groups/7/members", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]member{{ID: 2, Username: "alice", AccessLevel: 30}})
	})
	mux.HandleFunc("/api/v4/groups/7/members/2", func(w http.ResponseWriter, _ *http.Request) {
		deleted = true
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store, _ := state.Open(filepath.Join(t.TempDir(), "state.json"))
	result, err := New("gitlab", srv.URL, "mutator", "resolver", "openid_connect", srv.Client(), store).SyncGroup(context.Background(), model.SyncRequest{
		RuleName: "teams", SourceGroup: model.Group{ID: "source", Path: "/team", Members: []model.User{{ID: "kc-alice", Username: "alice"}}},
		TargetPath: "team", AccessLevel: "developer", AdoptExistingGroup: true,
		Prune: "authoritative", MaxRemovals: 10, IdentityMatch: []string{"oidc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Unresolved != 1 || deleted {
		t.Fatalf("result=%+v deleted=%t", result, deleted)
	}
}

func TestFindUserOIDCRequiresExactIdentityAndResolverToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "resolver" {
			t.Fatalf("wrong resolver token")
		}
		json.NewEncoder(w).Encode([]user{
			{ID: 1, Username: "wrong", Identities: []identity{{Provider: "other", ExternUID: "kc-user"}}},
			{ID: 2, Username: "right", Identities: []identity{{Provider: "openid_connect", ExternUID: "kc-user"}}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store, _ := state.Open(filepath.Join(t.TempDir(), "state.json"))
	found, ok, err := New("gitlab", srv.URL, "mutator", "resolver", "openid_connect", srv.Client(), store).findUser(
		context.Background(), model.User{ID: "kc-user"}, []string{"oidc"})
	if err != nil || !ok || found.ID != 2 {
		t.Fatalf("found=%+v ok=%t err=%v", found, ok, err)
	}
}

func TestCredentialFilesReloadForEveryRequestAndRefreshCurrentIdentity(t *testing.T) {
	dir := t.TempDir()
	mutationPath := filepath.Join(dir, "gitlab-token")
	resolverPath := filepath.Join(dir, "gitlab-resolver-token")
	if err := os.WriteFile(mutationPath, []byte("mutation-one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolverPath, []byte("resolver-one"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutation, err := credential.New("", mutationPath)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := credential.New("", resolverPath)
	if err != nil {
		t.Fatal(err)
	}

	var groupTokens, resolverTokens, identityTokens []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/groups/team", func(w http.ResponseWriter, r *http.Request) {
		groupTokens = append(groupTokens, r.Header.Get("PRIVATE-TOKEN"))
		json.NewEncoder(w).Encode(group{ID: 7, FullPath: "team"})
	})
	mux.HandleFunc("/api/v4/users", func(w http.ResponseWriter, r *http.Request) {
		resolverTokens = append(resolverTokens, r.Header.Get("PRIVATE-TOKEN"))
		json.NewEncoder(w).Encode([]user{{ID: 1, Username: "alice", State: "active"}})
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("PRIVATE-TOKEN")
		identityTokens = append(identityTokens, token)
		id := 1
		if token == "mutation-two" {
			id = 2
		}
		json.NewEncoder(w).Encode(user{ID: id, Username: "sync-bot", State: "active"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	store, err := state.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	client := NewWithCredentials("gitlab", server.URL, mutation, resolver, "openid_connect", server.Client(), store)

	assertRequestCredentials := func(wantIdentity int) {
		t.Helper()
		if found, err := client.getGroup(context.Background(), "team"); err != nil || found == nil {
			t.Fatalf("getGroup() = %+v, %v", found, err)
		}
		if _, found, err := client.findUser(context.Background(), model.User{Username: "alice"}, []string{"username"}); err != nil || !found {
			t.Fatalf("findUser() found=%t err=%v", found, err)
		}
		if id, err := client.currentIdentity(context.Background()); err != nil || id != wantIdentity {
			t.Fatalf("currentIdentity() = %d, %v; want %d", id, err, wantIdentity)
		}
	}
	assertRequestCredentials(1)
	if err := os.WriteFile(mutationPath, []byte("mutation-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolverPath, []byte("resolver-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRequestCredentials(2)

	if got := groupTokens; len(got) != 2 || got[0] != "mutation-one" || got[1] != "mutation-two" {
		t.Fatalf("mutation request tokens = %#v", got)
	}
	if got := resolverTokens; len(got) != 2 || got[0] != "resolver-one" || got[1] != "resolver-two" {
		t.Fatalf("resolver request tokens = %#v", got)
	}
	if got := identityTokens; len(got) != 2 || got[0] != "mutation-one" || got[1] != "mutation-two" {
		t.Fatalf("identity request tokens = %#v", got)
	}
}

func TestAuthoritativePruneRequiresOwnedOrAdoptedGroup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/groups/team", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(group{ID: 7, FullPath: "team"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store, _ := state.Open(filepath.Join(t.TempDir(), "state.json"))
	_, err := New("gitlab", srv.URL, "mutator", "resolver", "openid_connect", srv.Client(), store).SyncGroup(context.Background(), model.SyncRequest{
		RuleName: "teams", SourceGroup: model.Group{ID: "source", Path: "/team"}, TargetPath: "team",
		AccessLevel: "developer", Prune: "authoritative", MaxRemovals: 10, IdentityMatch: []string{"username"},
	})
	if err == nil {
		t.Fatal("expected authoritative adoption error")
	}
}

func TestCanonicalStateKeyHandlesUUIDChurnAndImmediateDeclaredRemoval(t *testing.T) {
	deleted := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(user{ID: 99})
	})
	mux.HandleFunc("/api/v4/groups/internal%2Fccmo", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(group{ID: 7, FullPath: "internal/ccmo"})
	})
	mux.HandleFunc("/api/v4/groups/7/members", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]member{{ID: 2, Username: "stale", AccessLevel: 30}})
	})
	mux.HandleFunc("/api/v4/groups/7/members/2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete ||
			r.URL.Query().Get("skip_subresources") != "true" ||
			r.URL.Query().Get("unassign_issuables") != "false" {
			t.Fatalf("unsafe declared removal: %s %s", r.Method, r.URL.String())
		}
		deleted++
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store, _ := state.Open(filepath.Join(t.TempDir(), "state.json"))
	client := New("gitlab", srv.URL, "token", "resolver", "openid_connect", srv.Client(), store)
	if err := store.PutGroup(state.GroupMapping{
		Provider: client.ownershipKey, Rule: "orgs", SourceGroupID: "/Internal/CCMO",
		SourceNativeID: "old-uuid", SourceGroupPath: "/Internal/CCMO",
		TargetGroupID: "7", TargetGroupPath: "internal/ccmo", Owned: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkManaged(client.ownershipKey, "7", "2"); err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncGroup(context.Background(), model.SyncRequest{
		RuleName: "orgs", StateKey: "/Internal/CCMO",
		SourceGroup: model.Group{ID: "new-uuid", Path: "/Internal/CCMO"},
		TargetPath:  "internal/ccmo", TargetParent: "internal",
		AccessLevel: "developer", Prune: "managed-only", MaxRemovals: 10,
		IdentityMatch: []string{"username"}, ImmediateRemoval: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Removed != 1 || deleted != 1 {
		t.Fatalf("declared removal result=%+v deleted=%d", result, deleted)
	}
	mapping, ok := store.Group(client.ownershipKey, "orgs", "/Internal/CCMO")
	if !ok || mapping.SourceNativeID != "new-uuid" || mapping.TargetGroupID != "7" {
		t.Fatalf("canonical mapping after UUID churn = %+v, %t", mapping, ok)
	}
}
