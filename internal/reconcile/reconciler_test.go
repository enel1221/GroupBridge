package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/enel1221/GroupBridge/internal/config"
	"github.com/enel1221/GroupBridge/internal/metrics"
	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/provider"
	"github.com/enel1221/GroupBridge/internal/state"
)

type fakeSource struct {
	groups []model.Group
	err    error
}

func (f fakeSource) ListGroups(context.Context) ([]model.Group, error) { return f.groups, f.err }

type fakeProvider struct{ requests []model.SyncRequest }

func (f *fakeProvider) Name() string                      { return "gitlab" }
func (f *fakeProvider) HealthCheck(context.Context) error { return nil }
func (f *fakeProvider) SyncGroup(_ context.Context, req model.SyncRequest) (model.Result, error) {
	f.requests = append(f.requests, req)
	return model.Result{Provider: "gitlab", SourceGroup: req.SourceGroup.Path, TargetGroup: req.TargetPath, Converged: true}, nil
}

type fakeAccessProvider struct{ requests []model.AccessSyncRequest }

func (f *fakeAccessProvider) Name() string                      { return "vault" }
func (f *fakeAccessProvider) HealthCheck(context.Context) error { return nil }
func (f *fakeAccessProvider) SyncAccessGroup(_ context.Context, req model.AccessSyncRequest) (model.AccessResult, error) {
	f.requests = append(f.requests, req)
	return model.AccessResult{
		Provider: "vault", SourceGroup: req.SourceGroup.Path, SecretPath: req.SecretPath,
		Converged: true,
	}, nil
}

func TestRunOnceMapsGroupsBelowPrefix(t *testing.T) {
	fp := &fakeProvider{}
	r := New(fakeSource{groups: []model.Group{
		{ID: "namespace", Path: "/gitlab"},
		{ID: "team", Path: "/gitlab/Team Platform"},
	}}, provider.NewRegistry(fp), []config.Rule{{
		Name: "teams", SourceGroupPrefix: "/gitlab", TargetProvider: "gitlab", TargetParent: "managed",
		AccessLevel: "developer", Prune: "managed-only", MaxRemovals: 10, IdentityMatch: []string{"oidc"},
	}}, mustStore(t), &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.requests) != 1 || fp.requests[0].TargetPath != "managed/team-platform" {
		t.Fatalf("requests = %#v", fp.requests)
	}
}

func TestRunOnceRejectsSlugCollisionBeforeMutation(t *testing.T) {
	fp := &fakeProvider{}
	r := New(fakeSource{groups: []model.Group{{ID: "1", Path: "/gitlab/A B"}, {ID: "2", Path: "/gitlab/A-B"}}},
		provider.NewRegistry(fp), []config.Rule{{Name: "r", SourceGroupPrefix: "/gitlab", TargetProvider: "gitlab", AccessLevel: "developer", Prune: "none"}},
		mustStore(t), &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected collision error")
	}
	if len(fp.requests) != 0 {
		t.Fatalf("provider was mutated: %#v", fp.requests)
	}
}

func TestRunOnceReconcilesDeletedSourceGroupAsTombstone(t *testing.T) {
	fp := &fakeProvider{}
	s := mustStore(t)
	if err := s.PutGroup(state.GroupMapping{
		Provider: "gitlab@fingerprint", Rule: "teams", SourceGroupID: "deleted",
		SourceGroupPath: "/gitlab/deleted", TargetGroupID: "7", TargetGroupPath: "platform/deleted", Owned: true,
	}); err != nil {
		t.Fatal(err)
	}
	r := New(fakeSource{}, provider.NewRegistry(fp), []config.Rule{{
		Name: "teams", SourceGroupPrefix: "/gitlab", TargetProvider: "gitlab", TargetParent: "platform",
		AccessLevel: "developer", Prune: "managed-only", MaxRemovals: 10, IdentityMatch: []string{"oidc"},
	}}, s, &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.requests) != 1 || fp.requests[0].SourceGroup.ID != "deleted" || len(fp.requests[0].SourceGroup.Members) != 0 {
		t.Fatalf("tombstone request = %#v", fp.requests)
	}
	if _, ok := s.Group("gitlab@fingerprint", "teams", "deleted"); ok {
		t.Fatal("converged tombstone was not retired")
	}
	fp.requests = nil
	r = New(fakeSource{groups: []model.Group{{ID: "replacement", Path: "/gitlab/deleted"}}}, provider.NewRegistry(fp), r.rules, s,
		&metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.requests) != 1 || fp.requests[0].TargetPath != "platform/deleted" {
		t.Fatalf("reused path request = %#v", fp.requests)
	}
}

func TestRunOnceKeepsStableTargetAcrossSourceRename(t *testing.T) {
	fp := &fakeProvider{}
	s := mustStore(t)
	if err := s.PutGroup(state.GroupMapping{
		Provider: "gitlab@fingerprint", Rule: "teams", SourceGroupID: "same-id",
		SourceGroupPath: "/gitlab/old", TargetGroupID: "7", TargetGroupPath: "platform/old", Owned: true,
	}); err != nil {
		t.Fatal(err)
	}
	r := New(fakeSource{groups: []model.Group{{ID: "same-id", Path: "/gitlab/new"}}}, provider.NewRegistry(fp), []config.Rule{{
		Name: "teams", SourceGroupPrefix: "/gitlab", TargetProvider: "gitlab", TargetParent: "platform",
		AccessLevel: "developer", Prune: "managed-only", MaxRemovals: 10, IdentityMatch: []string{"oidc"},
	}}, s, &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.requests) != 1 || fp.requests[0].TargetPath != "platform/old" {
		t.Fatalf("renamed request = %#v", fp.requests)
	}
}

func TestRunOnceMapsVaultHierarchyWithoutProvisioningUsers(t *testing.T) {
	fp := &fakeAccessProvider{}
	r := New(fakeSource{groups: []model.Group{
		{ID: "parent", Path: "/Internal/CCMO", Members: []model.User{{ID: "ignored"}}},
		{ID: "child", Path: "/Internal/CCMO/J6", Members: []model.User{{ID: "also-ignored"}}},
	}}, provider.NewRegistry(fp), []config.Rule{{
		Name: "vault-orgs", SourceGroupPrefix: "/Internal", TargetProvider: "vault", Prune: "none",
		Vault: &config.VaultRule{PathPrefix: "internal", AccessProfile: "editor"},
	}}, mustStore(t), &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.requests) != 2 {
		t.Fatalf("requests = %#v", fp.requests)
	}
	if fp.requests[0].SecretPath != "internal/ccmo" || fp.requests[1].SecretPath != "internal/ccmo/j6" {
		t.Fatalf("hierarchy was not preserved: %#v", fp.requests)
	}
	if fp.requests[0].SourceGroup.Path != "/Internal/CCMO" || fp.requests[1].SourceGroup.Path != "/Internal/CCMO/J6" {
		t.Fatalf("source paths were not preserved: %#v", fp.requests)
	}
	if len(fp.requests[0].SourceGroup.Members) != 0 || len(fp.requests[1].SourceGroup.Members) != 0 {
		t.Fatalf("Vault access request must not provision users: %#v", fp.requests)
	}
}

func TestRunOnceIncompleteSnapshotMakesNoVaultMutations(t *testing.T) {
	fp := &fakeAccessProvider{}
	r := New(fakeSource{err: errors.New("pagination failed")}, provider.NewRegistry(fp), []config.Rule{{
		Name: "vault-orgs", SourceGroupPrefix: "/Internal", TargetProvider: "vault", Prune: "none",
		Vault: &config.VaultRule{PathPrefix: "internal", AccessProfile: "editor"},
	}}, mustStore(t), &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected snapshot error")
	}
	if len(fp.requests) != 0 {
		t.Fatalf("Vault was mutated after incomplete snapshot: %#v", fp.requests)
	}
}

func TestRunOnceRejectsVaultPathCollisionBeforeMutation(t *testing.T) {
	fp := &fakeAccessProvider{}
	r := New(fakeSource{groups: []model.Group{
		{ID: "1", Path: "/Internal/Team"},
		{ID: "2", Path: "/Internal/team"},
	}}, provider.NewRegistry(fp), []config.Rule{{
		Name: "vault-orgs", SourceGroupPrefix: "/Internal", TargetProvider: "vault", Prune: "none",
		Vault: &config.VaultRule{PathPrefix: "internal", AccessProfile: "editor"},
	}}, mustStore(t), &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected collision error")
	}
	if len(fp.requests) != 0 {
		t.Fatalf("Vault was mutated before collision validation: %#v", fp.requests)
	}
}

func TestVaultSecretPathRejectsUnsafeSegments(t *testing.T) {
	for _, path := range []string{
		"internal/..", "internal/a b", "internal/a%2fb", "internal/a+b",
		"internal/a*b", "internal/a\"b", "internal/a\nb", "internal/é",
		strings.Repeat("a", 64),
	} {
		t.Run(strings.ReplaceAll(path, "/", "_"), func(t *testing.T) {
			if _, err := vaultSecretPath("", path); err == nil {
				t.Fatalf("vaultSecretPath(%q) unexpectedly succeeded", path)
			}
		})
	}
	if got, err := vaultSecretPath("internal", "CCMO/J6"); err != nil || got != "internal/ccmo/j6" {
		t.Fatalf("valid nested path got %q, %v", got, err)
	}
}

func TestVaultRuleDoesNotMutateGroupMembersForGitLabInEitherOrder(t *testing.T) {
	for _, vaultFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "vault-first", false: "gitlab-first"}[vaultFirst], func(t *testing.T) {
			gitlab := &fakeProvider{}
			vault := &fakeAccessProvider{}
			vaultRule := config.Rule{
				Name: "vault", SourceGroupPrefix: "/Internal", TargetProvider: "vault", Prune: "none",
				Vault: &config.VaultRule{PathPrefix: "internal", AccessProfile: "editor"},
			}
			gitlabRule := config.Rule{
				Name: "gitlab", SourceGroupPrefix: "/Internal", TargetProvider: "gitlab",
				TargetParent: "internal", AccessLevel: "developer", Prune: "managed-only",
			}
			rules := []config.Rule{gitlabRule, vaultRule}
			if vaultFirst {
				rules = []config.Rule{vaultRule, gitlabRule}
			}
			r := New(fakeSource{groups: []model.Group{{
				ID: "group", Path: "/Internal/CCMO",
				Members: []model.User{{ID: "user"}},
			}}}, provider.NewRegistry(gitlab, vault), rules, mustStore(t), &metrics.Metrics{},
				slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			if err := r.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(gitlab.requests) != 1 || len(gitlab.requests[0].SourceGroup.Members) != 1 {
				t.Fatalf("GitLab desired members were mutated: %#v", gitlab.requests)
			}
			if len(vault.requests) != 1 || len(vault.requests[0].SourceGroup.Members) != 0 {
				t.Fatalf("Vault request carried users: %#v", vault.requests)
			}
		})
	}
}

func TestExactAllowlistIgnoresUndeclaredAndHoldsDeclaredAbsence(t *testing.T) {
	fp := &fakeAccessProvider{}
	s := mustStore(t)
	rule := config.Rule{
		Name: "vault-orgs", SourceGroupPrefix: "/Internal",
		SourceGroupPaths: []string{"/Internal/CCMO"},
		TargetProvider:   "vault", Prune: "none",
		Vault: &config.VaultRule{PathPrefix: "internal", AccessProfile: "editor"},
	}
	r := New(fakeSource{groups: []model.Group{{ID: "other", Path: "/Internal/Undeclared"}}},
		provider.NewRegistry(fp), []config.Rule{rule}, s, &metrics.Metrics{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fp.requests) != 0 {
		t.Fatalf("exact allowlist caused mutations: %#v", fp.requests)
	}
}

func TestExactAllowlistMigratesLegacyGitLabUUIDMappingAndHandlesUUIDChurn(t *testing.T) {
	fp := &fakeProvider{}
	s := mustStore(t)
	if err := s.PutGroup(state.GroupMapping{
		Provider: "gitlab@fingerprint", Rule: "orgs", SourceGroupID: "old-uuid",
		SourceGroupPath: "/Internal/CCMO", TargetGroupID: "7",
		TargetGroupPath: "internal/ccmo", Owned: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkManaged("gitlab@fingerprint", "7", "user-1"); err != nil {
		t.Fatal(err)
	}
	r := New(fakeSource{groups: []model.Group{{ID: "new-uuid", Path: "/Internal/CCMO"}}},
		provider.NewRegistry(fp), []config.Rule{{
			Name: "orgs", SourceGroupPrefix: "/Internal",
			SourceGroupPaths: []string{"/Internal/CCMO"},
			TargetProvider:   "gitlab", TargetParent: "internal",
			AccessLevel: "developer", Prune: "managed-only",
		}}, s, &metrics.Metrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Group("gitlab@fingerprint", "orgs", "old-uuid"); ok {
		t.Fatal("legacy UUID-keyed mapping remains")
	}
	mapping, ok := s.Group("gitlab@fingerprint", "orgs", "/Internal/CCMO")
	if !ok || mapping.SourceNativeID != "new-uuid" || !mapping.Owned {
		t.Fatalf("canonical mapping = %+v, %t", mapping, ok)
	}
	if !s.IsManaged("gitlab@fingerprint", "7", "user-1") {
		t.Fatal("membership ledger was lost")
	}
	if len(fp.requests) != 1 || fp.requests[0].StateKey != "/Internal/CCMO" {
		t.Fatalf("canonical request = %#v", fp.requests)
	}
}

func mustStore(t *testing.T) *state.Store {
	t.Helper()
	s, err := state.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
