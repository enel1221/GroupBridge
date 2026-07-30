package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

type targetedFakeSource struct {
	groups    []model.Group
	target    model.Group
	found     bool
	listErr   error
	targetErr error
	listCalls atomic.Int32
	readCalls atomic.Int32
}

type multiTargetSource struct {
	initial   []model.Group
	current   map[string]model.Group
	readCalls atomic.Int32
}

func (f *multiTargetSource) ListGroups(context.Context) ([]model.Group, error) {
	return f.initial, nil
}

func (f *multiTargetSource) ReadGroup(_ context.Context, groupID string) (model.Group, bool, error) {
	f.readCalls.Add(1)
	group, found := f.current[groupID]
	return group, found, nil
}

func (f *targetedFakeSource) ListGroups(context.Context) ([]model.Group, error) {
	f.listCalls.Add(1)
	return f.groups, f.listErr
}

func (f *targetedFakeSource) ReadGroup(context.Context, string) (model.Group, bool, error) {
	f.readCalls.Add(1)
	return f.target, f.found, f.targetErr
}

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

func TestMembershipEventReadsOnlyOneGroupAcrossFiveThousandAndSkipsVault(t *testing.T) {
	const groupCount = 5_000
	groups := make([]model.Group, 0, groupCount)
	for index := range groupCount {
		groups = append(groups, model.Group{
			ID:   fmt.Sprintf("group-%d", index),
			Path: fmt.Sprintf("/Internal/Team-%d", index),
			Members: []model.User{{
				ID: fmt.Sprintf("user-%d", index),
			}},
		})
	}
	target := groups[groupCount/2]
	src := &targetedFakeSource{groups: groups, target: target, found: true}
	gitlab := &fakeProvider{}
	vault := &fakeAccessProvider{}
	m := &metrics.Metrics{}
	r := New(src, provider.NewRegistry(gitlab, vault), []config.Rule{
		{
			Name: "gitlab", SourceGroupPrefix: "/Internal", TargetProvider: "gitlab",
			TargetParent: "internal", AccessLevel: "developer", Prune: "managed-only",
		},
		{
			Name: "vault", SourceGroupPrefix: "/Internal", TargetProvider: "vault",
			Prune: "none", Vault: &config.VaultRule{
				PathPrefix: "internal", AccessProfile: "editor",
			},
		},
	}, mustStore(t), m, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	secret := &mutableRoutingSecret{value: strings.Repeat("s", 32)}
	r.ConfigureEventRouting(secret, "engineering")
	if err := r.routes.Replace(groups); err != nil {
		t.Fatal(err)
	}
	groupKey, found := r.routes.RouteForGroup(target.ID)
	if !found {
		t.Fatal("target group route is missing")
	}

	r.processEventBatch(context.Background(), eventBatch{
		groups: map[string]eventWork{groupKey: {}},
		users:  map[string]eventUserWork{},
	})

	if got := src.listCalls.Load(); got != 0 {
		t.Fatalf("complete tree reads = %d, want 0", got)
	}
	if got := src.readCalls.Load(); got != 1 {
		t.Fatalf("targeted group reads = %d, want 1", got)
	}
	if len(gitlab.requests) != 1 || gitlab.requests[0].SourceGroup.ID != target.ID {
		t.Fatalf("GitLab requests = %#v", gitlab.requests)
	}
	if len(vault.requests) != 0 {
		t.Fatalf("membership hint caused Vault work: %#v", vault.requests)
	}
	if got := m.EventTargetedRuns.Load(); got != 1 {
		t.Fatalf("targeted reconcile metric = %d, want 1", got)
	}
}

func TestTargetedSourceFailureOrMissingGroupCausesNoTargetMutation(t *testing.T) {
	for name, source := range map[string]*targetedFakeSource{
		"failed-read": {
			targetErr: errors.New("partial member page failed"),
		},
		"missing-group": {
			found: false,
		},
		"outside-allowlist": {
			target: model.Group{ID: "group-1", Path: "/Other/Team"},
			found:  true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			gitlab := &fakeProvider{}
			r := New(source, provider.NewRegistry(gitlab), []config.Rule{{
				Name: "gitlab", SourceGroupPrefix: "/Internal",
				SourceGroupPaths: []string{"/Internal/Team"},
				TargetProvider:   "gitlab", TargetParent: "internal",
				AccessLevel: "developer", Prune: "managed-only",
			}}, mustStore(t), &metrics.Metrics{},
				slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
			err := r.RunGroupOnce(context.Background(), "group-1", true)
			if name == "failed-read" && err == nil {
				t.Fatal("expected source read failure")
			}
			if name != "failed-read" && err != nil {
				t.Fatal(err)
			}
			if len(gitlab.requests) != 0 {
				t.Fatalf("target was mutated: %#v", gitlab.requests)
			}
		})
	}
}

func TestFailedFullRepairKeepsKnownKeyedWorkAndRequeuesTopologyRepair(t *testing.T) {
	group := model.Group{ID: "known", Path: "/Internal/Known"}
	src := &targetedFakeSource{
		groups: []model.Group{group}, target: group, found: true,
		listErr: errors.New("root group page failed"),
	}
	gitlab := &fakeProvider{}
	r := New(src, provider.NewRegistry(gitlab), []config.Rule{{
		Name: "gitlab", SourceGroupPrefix: "/Internal",
		TargetProvider: "gitlab", TargetParent: "internal",
		AccessLevel: "developer", Prune: "managed-only",
	}}, mustStore(t), &metrics.Metrics{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	secret := &mutableRoutingSecret{value: strings.Repeat("s", 32)}
	r.ConfigureEventRouting(secret, "engineering")
	if err := r.routes.Replace([]model.Group{group}); err != nil {
		t.Fatal(err)
	}
	knownKey, _ := r.routes.RouteForGroup(group.ID)
	r.processEventBatch(context.Background(), eventBatch{
		groups: map[string]eventWork{
			knownKey:                {},
			strings.Repeat("f", 64): {},
		},
		users: map[string]eventUserWork{},
	})

	if got := src.listCalls.Load(); got != 1 {
		t.Fatalf("full repair calls = %d, want 1", got)
	}
	if got := src.readCalls.Load(); got != 1 {
		t.Fatalf("known targeted reads = %d, want 1", got)
	}
	if len(gitlab.requests) != 1 || gitlab.requests[0].SourceGroup.ID != group.ID {
		t.Fatalf("known work was dropped: %#v", gitlab.requests)
	}
	r.events.mu.Lock()
	delayedRepairs := len(r.events.delayed)
	r.events.mu.Unlock()
	if delayedRepairs != 1 {
		t.Fatalf("delayed topology repairs = %d, want 1", delayedRepairs)
	}
	r.events.Close()
}

func TestDirectUserDeleteConfirmsEveryPriorGroupWithinSeconds(t *testing.T) {
	user := model.User{ID: "deleted-user"}
	initial := []model.Group{
		{ID: "group-1", Path: "/Internal/One", Members: []model.User{user}},
		{ID: "group-2", Path: "/Internal/Two", Members: []model.User{user}},
		{ID: "group-3", Path: "/Internal/Three", Members: []model.User{user}},
	}
	current := make(map[string]model.Group, len(initial))
	for _, group := range initial {
		group.Members = nil
		current[group.ID] = group
	}
	src := &multiTargetSource{initial: initial, current: current}
	gitlab := &fakeProvider{}
	r := New(src, provider.NewRegistry(gitlab), []config.Rule{{
		Name: "gitlab", SourceGroupPrefix: "/Internal",
		TargetProvider: "gitlab", TargetParent: "internal",
		AccessLevel: "developer", Prune: "managed-only",
	}}, mustStore(t), &metrics.Metrics{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	secret := &mutableRoutingSecret{value: strings.Repeat("s", 32)}
	r.ConfigureEventRouting(secret, "engineering")
	if err := r.routes.Replace(initial); err != nil {
		t.Fatal(err)
	}
	userKey := routingKey(
		[]byte(strings.Repeat("s", 32)), "user", "engineering", user.ID,
	)
	r.processEventBatch(context.Background(), eventBatch{
		groups: map[string]eventWork{},
		users: map[string]eventUserWork{
			userKey: {confirmMembership: true},
		},
	})
	if got := src.readCalls.Load(); got != 3 {
		t.Fatalf("first authoritative reads = %d, want 3", got)
	}

	select {
	case <-r.events.Wake():
	case <-time.After(3 * time.Second):
		t.Fatal("second membership confirmation was not scheduled")
	}
	r.processEventBatch(context.Background(), r.events.Drain())
	if got := src.readCalls.Load(); got != 6 {
		t.Fatalf("authoritative reads after confirmation = %d, want 6", got)
	}
	if len(gitlab.requests) != 6 {
		t.Fatalf("provider requests = %d, want two guarded reads for each group", len(gitlab.requests))
	}
	r.events.Close()
}

func mustStore(t *testing.T) *state.Store {
	t.Helper()
	s, err := state.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
