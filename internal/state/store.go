// Package state records only memberships that GroupBridge created or already owned.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

type Membership struct {
	Provider string `json:"provider"`
	GroupID  string `json:"groupId"`
	UserID   string `json:"userId"`
}

type GroupMapping struct {
	Provider        string `json:"provider"`
	Rule            string `json:"rule"`
	SourceGroupID   string `json:"sourceGroupId"`
	SourceGroupPath string `json:"sourceGroupPath"`
	TargetGroupID   string `json:"targetGroupId"`
	TargetGroupPath string `json:"targetGroupPath"`
	Owned           bool   `json:"owned"`
}

type Absence struct {
	Provider     string `json:"provider"`
	GroupID      string `json:"groupId"`
	UserID       string `json:"userId"`
	Observations int    `json:"observations"`
}

type diskState struct {
	Version       int            `json:"version"`
	Memberships   []Membership   `json:"managedMemberships"`
	GroupMappings []GroupMapping `json:"groupMappings"`
	Absences      []Absence      `json:"absenceObservations"`
}

type Store struct {
	mu       sync.RWMutex
	path     string
	records  map[string]Membership
	groups   map[string]GroupMapping
	absences map[string]Absence
	lockFile *os.File
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, errors.New("state is already locked by another GroupBridge process")
	}
	s := &Store{path: path, records: make(map[string]Membership), groups: make(map[string]GroupMapping), absences: make(map[string]Absence), lockFile: lockFile}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("read state: %w", err)
	}
	var data diskState
	if err := json.Unmarshal(b, &data); err != nil {
		s.Close()
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if data.Version != 2 {
		s.Close()
		return nil, fmt.Errorf("unsupported state version %d", data.Version)
	}
	for _, m := range data.Memberships {
		s.records[key(m.Provider, m.GroupID, m.UserID)] = m
	}
	for _, g := range data.GroupMappings {
		s.groups[groupKey(g.Provider, g.Rule, g.SourceGroupID)] = g
	}
	for _, a := range data.Absences {
		s.absences[key(a.Provider, a.GroupID, a.UserID)] = a
	}
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockFile == nil {
		return nil
	}
	if err := syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("unlock state: %w", err)
	}
	err := s.lockFile.Close()
	s.lockFile = nil
	return err
}

func (s *Store) IsManaged(provider, groupID, userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.records[key(provider, groupID, userID)]
	return ok
}

func (s *Store) MarkManaged(provider, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := Membership{Provider: provider, GroupID: groupID, UserID: userID}
	k := key(provider, groupID, userID)
	previous, existed := s.records[k]
	s.records[k] = m
	if err := s.saveLocked(); err != nil {
		if existed {
			s.records[k] = previous
		} else {
			delete(s.records, k)
		}
		return err
	}
	return nil
}

func (s *Store) Unmark(provider, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(provider, groupID, userID)
	previous, existed := s.records[k]
	delete(s.records, k)
	if err := s.saveLocked(); err != nil {
		if existed {
			s.records[k] = previous
		}
		return err
	}
	return nil
}

func (s *Store) Group(provider, rule, sourceGroupID string) (GroupMapping, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[groupKey(provider, rule, sourceGroupID)]
	return g, ok
}

func (s *Store) GroupMappings() []GroupMapping {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]GroupMapping, 0, len(s.groups))
	for _, g := range s.groups {
		result = append(result, g)
	}
	sort.Slice(result, func(i, j int) bool {
		return groupKey(result[i].Provider, result[i].Rule, result[i].SourceGroupID) < groupKey(result[j].Provider, result[j].Rule, result[j].SourceGroupID)
	})
	return result
}

func (s *Store) PutGroup(mapping GroupMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := groupKey(mapping.Provider, mapping.Rule, mapping.SourceGroupID)
	previous, existed := s.groups[k]
	s.groups[k] = mapping
	if err := s.saveLocked(); err != nil {
		if existed {
			s.groups[k] = previous
		} else {
			delete(s.groups, k)
		}
		return err
	}
	return nil
}

func (s *Store) DeleteGroup(provider, rule, sourceGroupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := groupKey(provider, rule, sourceGroupID)
	previous, existed := s.groups[k]
	if !existed {
		return nil
	}
	delete(s.groups, k)
	if err := s.saveLocked(); err != nil {
		s.groups[k] = previous
		return err
	}
	return nil
}

// ConfirmAbsent returns true only after the same missing membership has been
// observed in two complete reconciliation snapshots.
func (s *Store) ConfirmAbsent(provider, groupID, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(provider, groupID, userID)
	previous, existed := s.absences[k]
	current := previous
	current.Provider, current.GroupID, current.UserID = provider, groupID, userID
	current.Observations++
	s.absences[k] = current
	if err := s.saveLocked(); err != nil {
		if existed {
			s.absences[k] = previous
		} else {
			delete(s.absences, k)
		}
		return false, err
	}
	return current.Observations >= 2, nil
}

func (s *Store) ResetAbsent(provider, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(provider, groupID, userID)
	previous, existed := s.absences[k]
	if !existed {
		return nil
	}
	delete(s.absences, k)
	if err := s.saveLocked(); err != nil {
		s.absences[k] = previous
		return err
	}
	return nil
}

func (s *Store) saveLocked() error {
	data := diskState{Version: 2, Memberships: make([]Membership, 0, len(s.records)), GroupMappings: make([]GroupMapping, 0, len(s.groups)), Absences: make([]Absence, 0, len(s.absences))}
	for _, m := range s.records {
		data.Memberships = append(data.Memberships, m)
	}
	for _, g := range s.groups {
		data.GroupMappings = append(data.GroupMappings, g)
	}
	for _, a := range s.absences {
		data.Absences = append(data.Absences, a)
	}
	sort.Slice(data.Memberships, func(i, j int) bool {
		a, b := data.Memberships[i], data.Memberships[j]
		return key(a.Provider, a.GroupID, a.UserID) < key(b.Provider, b.GroupID, b.UserID)
	})
	sort.Slice(data.GroupMappings, func(i, j int) bool {
		a, b := data.GroupMappings[i], data.GroupMappings[j]
		return groupKey(a.Provider, a.Rule, a.SourceGroupID) < groupKey(b.Provider, b.Rule, b.SourceGroupID)
	})
	sort.Slice(data.Absences, func(i, j int) bool {
		a, b := data.Absences[i], data.Absences[j]
		return key(a.Provider, a.GroupID, a.UserID) < key(b.Provider, b.GroupID, b.UserID)
	})
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".groupbridge-state-*")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	if err := dir.Sync(); err != nil {
		dir.Close()
		return fmt.Errorf("sync state directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close state directory: %w", err)
	}
	return nil
}

func key(provider, groupID, userID string) string {
	return provider + "\x00" + groupID + "\x00" + userID
}

func groupKey(provider, rule, sourceGroupID string) string {
	return provider + "\x00" + rule + "\x00" + sourceGroupID
}
