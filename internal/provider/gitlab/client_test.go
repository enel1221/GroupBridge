package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

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
