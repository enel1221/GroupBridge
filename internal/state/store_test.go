package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePersistsManagedMembership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.IsManaged("gitlab", "1", "2") {
		t.Fatal("new membership unexpectedly managed")
	}
	if err := s.MarkManaged("gitlab", "1", "2"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGroup(GroupMapping{Provider: "gitlab", Rule: "teams", SourceGroupID: "source-1", TargetGroupID: "1", TargetGroupPath: "teams", Owned: true}); err != nil {
		t.Fatal(err)
	}
	if confirmed, err := s.ConfirmAbsent("gitlab", "1", "3"); err != nil || confirmed {
		t.Fatalf("first absence confirmed=%t err=%v", confirmed, err)
	}
	if confirmed, err := s.ConfirmAbsent("gitlab", "1", "3"); err != nil || !confirmed {
		t.Fatalf("second absence confirmed=%t err=%v", confirmed, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.IsManaged("gitlab", "1", "2") {
		t.Fatal("membership was not persisted")
	}
	if mapping, ok := reloaded.Group("gitlab", "teams", "source-1"); !ok || !mapping.Owned || mapping.TargetGroupPath != "teams" {
		t.Fatalf("group mapping was not persisted: %+v, %t", mapping, ok)
	}
	if err := reloaded.Unmark("gitlab", "1", "2"); err != nil {
		t.Fatal(err)
	}
	if reloaded.IsManaged("gitlab", "1", "2") {
		t.Fatal("membership was not removed")
	}
	if err := reloaded.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreMigratesVersionTwoWithoutLosingGitLabState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	v2 := `{
  "version": 2,
  "managedMemberships": [{"provider":"gitlab@old","groupId":"1","userId":"2"}],
  "groupMappings": [{"provider":"gitlab@old","rule":"teams","sourceGroupId":"source-1","sourceGroupPath":"/teams/one","targetGroupId":"1","targetGroupPath":"teams/one","owned":true}],
  "absenceObservations": []
}`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsManaged("gitlab@old", "1", "2") {
		t.Fatal("v2 GitLab membership was lost")
	}
	mapping, ok := s.Group("gitlab@old", "teams", "source-1")
	if !ok || mapping.TargetGroupPath != "teams/one" {
		t.Fatalf("v2 GitLab group mapping was lost: %+v, %t", mapping, ok)
	}
	if err := s.PutGroup(GroupMapping{
		Provider: "gitlab@new", Rule: "orgs", SourceGroupID: "/Internal/CCMO",
		SourceNativeID: "source-2", TargetGroupID: "gitlab-group-id",
		TargetGroupPath: "internal/ccmo", Owned: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": 3`) || !strings.Contains(string(data), `"sourceNativeId": "source-2"`) {
		t.Fatalf("state was not migrated to v3:\n%s", data)
	}
}

func TestMoveGroupAtomicallyRekeysCanonicalPathAndPreservesMemberships(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.MarkManaged("gitlab@target", "group-1", "user-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGroup(GroupMapping{
		Provider: "gitlab@target", Rule: "orgs", SourceGroupID: "old-uuid",
		SourceGroupPath: "/Internal/CCMO", TargetGroupID: "group-1",
		TargetGroupPath: "internal/ccmo", Owned: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.MoveGroup("gitlab@target", "orgs", "old-uuid", "/Internal/CCMO", "new-uuid", "/Internal/CCMO"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Group("gitlab@target", "orgs", "old-uuid"); ok {
		t.Fatal("legacy UUID mapping still exists")
	}
	mapping, ok := s.Group("gitlab@target", "orgs", "/Internal/CCMO")
	if !ok || mapping.SourceNativeID != "new-uuid" || !mapping.Owned {
		t.Fatalf("canonical mapping = %+v, %t", mapping, ok)
	}
	if !s.IsManaged("gitlab@target", "group-1", "user-1") {
		t.Fatal("membership ownership was lost during mapping migration")
	}
}
