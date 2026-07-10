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
