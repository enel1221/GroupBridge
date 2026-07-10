package state

import (
	"path/filepath"
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
