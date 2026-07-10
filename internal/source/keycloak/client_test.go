package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestListGroupsReadsChildrenAndEnabledMembers(t *testing.T) {
	var tokenCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/demo/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		if err := r.ParseForm(); err != nil || r.Form.Get("client_secret") != "secret" {
			t.Fatalf("unexpected token form: %v", r.Form)
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
	})
	mux.HandleFunc("/admin/realms/demo/groups", func(w http.ResponseWriter, r *http.Request) {
		assertAuth(t, r)
		if r.URL.Query().Get("first") != "0" {
			json.NewEncoder(w).Encode([]any{})
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{{"id": "g1", "name": "gitlab", "path": "/gitlab", "subGroupCount": 1}})
	})
	mux.HandleFunc("/admin/realms/demo/groups/g1/children", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("first") != "0" {
			json.NewEncoder(w).Encode([]any{})
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{{"id": "g2", "name": "developers", "path": "/gitlab/developers"}})
	})
	mux.HandleFunc("/admin/realms/demo/groups/g2/children", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc("/admin/realms/demo/groups/g1/members", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc("/admin/realms/demo/groups/g2/members", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("first") != "0" {
			json.NewEncoder(w).Encode([]any{})
			return
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": "u1", "username": "alice", "email": "alice@example.test", "enabled": true},
			{"id": "u2", "username": "disabled", "enabled": false},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := New(srv.URL, "demo", "client", "secret", srv.Client())
	groups, err := client.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("ListGroups() error = %v", err)
	}
	if len(groups) != 2 || groups[1].Path != "/gitlab/developers" || len(groups[1].Members) != 1 || groups[1].Members[0].Username != "alice" {
		t.Fatalf("unexpected groups: %#v", groups)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d, want 1", tokenCalls.Load())
	}
}

func TestListGroupsDoesNotLeakAPIResponse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/demo/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
	})
	mux.HandleFunc("/admin/realms/demo/groups", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sensitive user data", http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := New(srv.URL, "demo", "client", "secret", srv.Client()).ListGroups(context.Background())
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("expected sanitized error, got %v", err)
	}
}

func TestListGroupsPaginatesMoreThanTwoHundredMembers(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/demo/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"access_token": "token", "expires_in": 300})
	})
	mux.HandleFunc("/admin/realms/demo/groups", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("first") == "0" {
			json.NewEncoder(w).Encode([]map[string]any{{"id": "g", "name": "team", "path": "/team"}})
			return
		}
		json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc("/admin/realms/demo/groups/g/children", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode([]any{}) })
	mux.HandleFunc("/admin/realms/demo/groups/g/members", func(w http.ResponseWriter, r *http.Request) {
		first, _ := strconv.Atoi(r.URL.Query().Get("first"))
		if first >= 205 {
			json.NewEncoder(w).Encode([]any{})
			return
		}
		end := min(first+100, 205)
		page := make([]map[string]any, 0, end-first)
		for i := first; i < end; i++ {
			page = append(page, map[string]any{"id": fmt.Sprintf("u-%d", i), "username": fmt.Sprintf("user-%d", i), "enabled": true})
		}
		json.NewEncoder(w).Encode(page)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	groups, err := New(srv.URL, "demo", "client", "secret", srv.Client()).ListGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Members) != 205 {
		t.Fatalf("groups=%d members=%d", len(groups), len(groups[0].Members))
	}
}

func assertAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("Authorization = %q", got)
	}
}
