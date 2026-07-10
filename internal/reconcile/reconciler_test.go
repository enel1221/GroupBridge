package reconcile

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/enel1221/GroupBridge/internal/config"
	"github.com/enel1221/GroupBridge/internal/metrics"
	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/provider"
	"github.com/enel1221/GroupBridge/internal/state"
)

type fakeSource struct{ groups []model.Group }

func (f fakeSource) ListGroups(context.Context) ([]model.Group, error) { return f.groups, nil }

type fakeProvider struct{ requests []model.SyncRequest }

func (f *fakeProvider) Name() string                      { return "gitlab" }
func (f *fakeProvider) HealthCheck(context.Context) error { return nil }
func (f *fakeProvider) SyncGroup(_ context.Context, req model.SyncRequest) (model.Result, error) {
	f.requests = append(f.requests, req)
	return model.Result{Provider: "gitlab", SourceGroup: req.SourceGroup.Path, TargetGroup: req.TargetPath, Converged: true}, nil
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

func mustStore(t *testing.T) *state.Store {
	t.Helper()
	s, err := state.Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
