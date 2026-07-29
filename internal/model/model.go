// Package model contains the provider-neutral desired-state model.
package model

import "time"

// User is an enabled identity returned by a source provider.
type User struct {
	ID       string
	Username string
	Email    string
}

// Group is a source group and its direct members.
type Group struct {
	ID      string
	Name    string
	Path    string
	Members []User
}

// SyncRequest describes the desired membership for one target group.
type SyncRequest struct {
	RuleName           string
	StateKey           string
	SourceGroup        Group
	TargetPath         string
	TargetParent       string
	CreateGroup        bool
	AdoptExistingGroup bool
	AccessLevel        string
	Prune              string
	ProtectedUsers     []string
	MaxRemovals        int
	IdentityMatch      []string
	EnforceAccessLevel bool
	ImmediateRemoval   bool
}

// Result summarizes a provider reconciliation without exposing secrets or PII.
type Result struct {
	Provider       string
	SourceGroup    string
	TargetGroup    string
	CreatedGroup   bool
	Added          int
	Updated        int
	Removed        int
	Unresolved     int
	SkippedRemoval int
	Converged      bool
	Duration       time.Duration
}

// AccessSyncRequest describes one source group's desired target-native access
// binding. It intentionally contains no users: providers such as Vault map the
// authoritative Keycloak group claim at login instead of provisioning people.
type AccessSyncRequest struct {
	RuleName      string
	StateKey      string
	SourceGroup   Group
	SecretPath    string
	AccessProfile string
	PolicyMode    string
	Discoverable  bool
}

// AccessResult summarizes access-object reconciliation without identities or
// policy contents.
type AccessResult struct {
	Provider       string
	SourceGroup    string
	SecretPath     string
	VerifiedPolicy bool
	Converged      bool
	Duration       time.Duration
}
