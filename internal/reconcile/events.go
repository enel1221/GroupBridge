package reconcile

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/enel1221/GroupBridge/internal/metrics"
	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/webhook"
)

const (
	maxDirtyRoutes            = 10_000
	eventSettleWindow         = 200 * time.Millisecond
	eventMaxDelay             = 2 * time.Second
	membershipConfirmDelay    = 1500 * time.Millisecond
	jitProvisioningRetryDelay = 3 * time.Second
	topologyRepairMinInterval = 5 * time.Second
)

type routingSecretLoader interface {
	Load() (string, error)
}

type routeIndex struct {
	mu     sync.RWMutex
	loader routingSecretLoader
	realm  string
	secret []byte

	groupIDs   map[string]string
	groupKeys  map[string]string
	userGroups map[string]map[string]struct{}
	groupUsers map[string]map[string]struct{}
}

func newRouteIndex(loader routingSecretLoader, realm string) *routeIndex {
	return &routeIndex{
		loader: loader, realm: realm,
		groupIDs: make(map[string]string), groupKeys: make(map[string]string),
		userGroups: make(map[string]map[string]struct{}),
		groupUsers: make(map[string]map[string]struct{}),
	}
}

func (i *routeIndex) Replace(groups []model.Group) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	secret, err := i.refreshSecretLocked()
	if err != nil {
		return err
	}
	i.groupUsers = make(map[string]map[string]struct{}, len(groups))
	for _, group := range groups {
		users := make(map[string]struct{}, len(group.Members))
		for _, user := range group.Members {
			if user.ID != "" {
				users[user.ID] = struct{}{}
			}
		}
		i.groupUsers[group.ID] = users
	}
	i.rebuildWithSecretLocked(secret)
	return nil
}

func (i *routeIndex) Update(group model.Group) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	secret, err := i.refreshSecretLocked()
	if err != nil {
		return err
	}
	for userID := range i.groupUsers[group.ID] {
		userKey := routingKey(secret, "user", i.realm, userID)
		delete(i.userGroups[userKey], group.ID)
		if len(i.userGroups[userKey]) == 0 {
			delete(i.userGroups, userKey)
		}
	}
	users := make(map[string]struct{}, len(group.Members))
	for _, user := range group.Members {
		if user.ID != "" {
			users[user.ID] = struct{}{}
			userKey := routingKey(secret, "user", i.realm, user.ID)
			groups := i.userGroups[userKey]
			if groups == nil {
				groups = make(map[string]struct{})
				i.userGroups[userKey] = groups
			}
			groups[group.ID] = struct{}{}
		}
	}
	i.groupUsers[group.ID] = users
	groupKey := routingKey(secret, "group", i.realm, group.ID)
	i.groupIDs[groupKey] = group.ID
	i.groupKeys[group.ID] = groupKey
	return nil
}

func (i *routeIndex) Refresh() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	_, err := i.refreshSecretLocked()
	return err
}

func (i *routeIndex) ResolveGroup(routeKey string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	groupID, found := i.groupIDs[routeKey]
	return groupID, found
}

func (i *routeIndex) ResolveUser(routeKey string) ([]string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	groupSet, found := i.userGroups[routeKey]
	if !found {
		return nil, false
	}
	groups := make([]string, 0, len(groupSet))
	for groupID := range groupSet {
		groups = append(groups, groupID)
	}
	return groups, true
}

func (i *routeIndex) RouteForGroup(groupID string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	routeKey, found := i.groupKeys[groupID]
	return routeKey, found
}

func (i *routeIndex) refreshSecretLocked() ([]byte, error) {
	secret, err := i.loader.Load()
	if err != nil {
		return nil, err
	}
	if len([]byte(secret)) < 32 {
		return nil, errors.New("routing secret must contain at least 32 bytes")
	}
	loaded := []byte(secret)
	if bytes.Equal(loaded, i.secret) {
		return i.secret, nil
	}
	clear(i.secret)
	i.secret = bytes.Clone(loaded)
	i.rebuildWithSecretLocked(i.secret)
	return i.secret, nil
}

func (i *routeIndex) rebuildWithSecretLocked(secret []byte) {
	i.groupIDs = make(map[string]string, len(i.groupUsers))
	i.groupKeys = make(map[string]string, len(i.groupUsers))
	i.userGroups = make(map[string]map[string]struct{})
	for groupID, users := range i.groupUsers {
		groupKey := routingKey(secret, "group", i.realm, groupID)
		i.groupIDs[groupKey] = groupID
		i.groupKeys[groupID] = groupKey
		for userID := range users {
			userKey := routingKey(secret, "user", i.realm, userID)
			groups := i.userGroups[userKey]
			if groups == nil {
				groups = make(map[string]struct{})
				i.userGroups[userKey] = groups
			}
			groups[groupID] = struct{}{}
		}
	}
}

func routingKey(secret []byte, domain, realm, identifier string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("groupbridge-route-v1\n"))
	mac.Write([]byte(domain))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(realm))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(identifier))
	return hex.EncodeToString(mac.Sum(nil))
}

type eventWork struct {
	allProviders   bool
	confirmRemoval bool
}

func (w eventWork) merge(other eventWork) eventWork {
	return eventWork{
		allProviders:   w.allProviders || other.allProviders,
		confirmRemoval: w.confirmRemoval || other.confirmRemoval,
	}
}

type eventBatch struct {
	groups       map[string]eventWork
	users        map[string]eventUserWork
	globalRepair bool
}

type eventUserWork struct {
	jitRetry          bool
	confirmMembership bool
}

func (w eventUserWork) merge(other eventUserWork) eventUserWork {
	return eventUserWork{
		jitRetry:          w.jitRetry || other.jitRetry,
		confirmMembership: w.confirmMembership || other.confirmMembership,
	}
}

type delayedWork struct {
	routeKey string
	reason   string
	work     eventWork
	due      time.Time
}

type eventQueue struct {
	mu      sync.Mutex
	groups  map[string]eventWork
	users   map[string]eventUserWork
	global  bool
	wake    chan struct{}
	delayed map[string]delayedWork
	timer   *time.Timer
	closed  bool
	metrics *metrics.Metrics
}

func newEventQueue(m *metrics.Metrics) *eventQueue {
	return &eventQueue{
		groups: make(map[string]eventWork), users: make(map[string]eventUserWork),
		wake: make(chan struct{}, 1), delayed: make(map[string]delayedWork),
		metrics: m,
	}
}

func (q *eventQueue) Add(hint webhook.Hint) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	if hint.GlobalRepair {
		q.globalLocked()
		return
	}
	if q.global {
		q.metrics.EventHintsCoalesced.Add(1)
		return
	}
	if hint.UserKey != "" {
		work := eventUserWork{
			jitRetry:          hint.OperationType == "LOGIN",
			confirmMembership: hint.OperationType == "UPDATE" || hint.OperationType == "DELETE",
		}
		if current, exists := q.users[hint.UserKey]; exists {
			q.users[hint.UserKey] = current.merge(work)
			q.metrics.EventHintsCoalesced.Add(1)
		} else {
			q.users[hint.UserKey] = work
		}
	} else if hint.GroupKey != "" {
		work := eventWork{
			allProviders:   hint.ResourceType == "GROUP",
			confirmRemoval: hint.ResourceType != "GROUP" && hint.OperationType == "DELETE",
		}
		if current, exists := q.groups[hint.GroupKey]; exists {
			q.groups[hint.GroupKey] = current.merge(work)
			q.metrics.EventHintsCoalesced.Add(1)
		} else {
			q.groups[hint.GroupKey] = work
		}
	} else {
		q.globalLocked()
		return
	}
	if len(q.groups)+len(q.users)+len(q.delayed) > maxDirtyRoutes {
		q.globalLocked()
		return
	}
	q.signalLocked()
}

func (q *eventQueue) AddGlobalAfter(delay time.Duration) {
	q.ScheduleGroup("", eventWork{}, delay, "global")
}

func (q *eventQueue) ScheduleGroup(
	routeKey string,
	work eventWork,
	delay time.Duration,
	reason string,
) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	key := reason + "\x00" + routeKey
	due := time.Now().Add(delay)
	if current, exists := q.delayed[key]; exists {
		current.due = due
		current.work = current.work.merge(work)
		q.delayed[key] = current
		q.metrics.EventHintsCoalesced.Add(1)
	} else {
		if len(q.groups)+len(q.users)+len(q.delayed) >= maxDirtyRoutes {
			q.globalLocked()
			return
		}
		q.delayed[key] = delayedWork{routeKey: routeKey, reason: reason, work: work, due: due}
	}
	q.resetTimerLocked()
}

func (q *eventQueue) Wake() <-chan struct{} { return q.wake }

func (q *eventQueue) Drain() eventBatch {
	q.mu.Lock()
	defer q.mu.Unlock()
	batch := eventBatch{groups: q.groups, users: q.users, globalRepair: q.global}
	q.groups = make(map[string]eventWork)
	q.users = make(map[string]eventUserWork)
	q.global = false
	return batch
}

func (q *eventQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	if q.timer != nil {
		q.timer.Stop()
		q.timer = nil
	}
}

func (q *eventQueue) globalLocked() {
	if q.global {
		q.metrics.EventHintsCoalesced.Add(1)
	}
	q.groups = make(map[string]eventWork)
	q.users = make(map[string]eventUserWork)
	q.delayed = make(map[string]delayedWork)
	q.global = true
	if q.timer != nil {
		q.timer.Stop()
		q.timer = nil
	}
	q.signalLocked()
}

func (q *eventQueue) signalLocked() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *eventQueue) resetTimerLocked() {
	if len(q.delayed) == 0 {
		if q.timer != nil {
			q.timer.Stop()
			q.timer = nil
		}
		return
	}
	var earliest time.Time
	for _, delayed := range q.delayed {
		if earliest.IsZero() || delayed.due.Before(earliest) {
			earliest = delayed.due
		}
	}
	wait := time.Until(earliest)
	if wait < 0 {
		wait = 0
	}
	if q.timer == nil {
		q.timer = time.AfterFunc(wait, q.releaseDue)
		return
	}
	q.timer.Stop()
	q.timer.Reset(wait)
}

func (q *eventQueue) releaseDue() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	now := time.Now()
	for key, delayed := range q.delayed {
		if delayed.due.After(now) {
			continue
		}
		delete(q.delayed, key)
		if delayed.reason == "global" {
			q.globalLocked()
			return
		}
		if !q.global {
			q.groups[delayed.routeKey] = q.groups[delayed.routeKey].merge(delayed.work)
		}
	}
	q.timer = nil
	q.resetTimerLocked()
	q.signalLocked()
}
