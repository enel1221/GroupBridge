package reconcile

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/enel1221/GroupBridge/internal/metrics"
	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/webhook"
)

type mutableRoutingSecret struct {
	mu    sync.RWMutex
	value string
}

type sequenceRoutingSecret struct {
	values []string
	calls  int
}

func (s *sequenceRoutingSecret) Load() (string, error) {
	index := s.calls
	if index >= len(s.values) {
		index = len(s.values) - 1
	}
	s.calls++
	return s.values[index], nil
}

func (s *mutableRoutingSecret) Load() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value, nil
}

func (s *mutableRoutingSecret) set(value string) {
	s.mu.Lock()
	s.value = value
	s.mu.Unlock()
}

func TestRoutingKeyMatchesJavaVectorAndSeparatesDomains(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	if got := routingKey(secret, "group", "engineering", "group-1"); got !=
		"992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0" {
		t.Fatalf("group routing key = %q", got)
	}
	if got := routingKey(secret, "user", "engineering", "private-user-id"); got !=
		"1ac5504a72c4b71c8377044145d8f48ec91bc9141188eef45794140332277008" {
		t.Fatalf("user routing key = %q", got)
	}
	if routingKey(secret, "group", "engineering", "same") ==
		routingKey(secret, "user", "engineering", "same") {
		t.Fatal("group and user routing domains collided")
	}
}

func TestRouteIndexRebuildsOnRestartAndSecretRotation(t *testing.T) {
	first := strings.Repeat("a", 32)
	second := strings.Repeat("b", 32)
	loader := &mutableRoutingSecret{value: first}
	groups := []model.Group{{
		ID: "group-1", Path: "/Internal/CCMO",
		Members: []model.User{{ID: "user-1"}},
	}}
	index := newRouteIndex(loader, "engineering")
	if err := index.Replace(groups); err != nil {
		t.Fatal(err)
	}
	firstGroupKey := routingKey([]byte(first), "group", "engineering", "group-1")
	firstUserKey := routingKey([]byte(first), "user", "engineering", "user-1")
	if groupID, found := index.ResolveGroup(firstGroupKey); !found || groupID != "group-1" {
		t.Fatalf("initial group route = %q, %t", groupID, found)
	}
	if groupIDs, found := index.ResolveUser(firstUserKey); !found ||
		len(groupIDs) != 1 || groupIDs[0] != "group-1" {
		t.Fatalf("initial user route = %#v, %t", groupIDs, found)
	}

	restarted := newRouteIndex(loader, "engineering")
	if err := restarted.Replace(groups); err != nil {
		t.Fatal(err)
	}
	if groupID, found := restarted.ResolveGroup(firstGroupKey); !found || groupID != "group-1" {
		t.Fatalf("restarted group route = %q, %t", groupID, found)
	}

	loader.set(second)
	if err := index.Refresh(); err != nil {
		t.Fatal(err)
	}
	secondGroupKey := routingKey([]byte(second), "group", "engineering", "group-1")
	if _, found := index.ResolveGroup(firstGroupKey); found {
		t.Fatal("old-secret routing key remained active after rotation")
	}
	if groupID, found := index.ResolveGroup(secondGroupKey); !found || groupID != "group-1" {
		t.Fatalf("rotated group route = %q, %t", groupID, found)
	}
	if _, found := index.ResolveGroup(strings.Repeat("f", 64)); found {
		t.Fatal("unknown routing key resolved")
	}
}

func TestRouteIndexUpdateUsesOneImmutableSecretGeneration(t *testing.T) {
	first := strings.Repeat("a", 32)
	second := strings.Repeat("b", 32)
	third := strings.Repeat("c", 32)
	loader := &sequenceRoutingSecret{values: []string{first, second, third}}
	index := newRouteIndex(loader, "engineering")
	groups := []model.Group{
		{ID: "group-1", Members: []model.User{{ID: "user-1"}}},
		{ID: "group-2", Members: []model.User{{ID: "user-2"}}},
	}
	if err := index.Replace(groups); err != nil {
		t.Fatal(err)
	}
	groups[0].Members = []model.User{{ID: "user-3"}}
	if err := index.Update(groups[0]); err != nil {
		t.Fatal(err)
	}
	if loader.calls != 2 {
		t.Fatalf("secret loads = %d, want exactly one per operation", loader.calls)
	}
	for _, group := range groups {
		key := routingKey([]byte(second), "group", "engineering", group.ID)
		if resolved, found := index.ResolveGroup(key); !found || resolved != group.ID {
			t.Fatalf("second-generation route for %q = %q, %t", group.ID, resolved, found)
		}
		mixed := routingKey([]byte(third), "group", "engineering", group.ID)
		if _, found := index.ResolveGroup(mixed); found {
			t.Fatalf("third-generation mixed route exists for %q", group.ID)
		}
	}
}

func TestEventQueueCoalescesTenThousandSameGroupHints(t *testing.T) {
	m := &metrics.Metrics{}
	queue := newEventQueue(m)
	defer queue.Close()
	groupKey := strings.Repeat("a", 64)
	for range 10_000 {
		queue.Add(webhook.Hint{
			ResourceType: "GROUP_MEMBERSHIP", OperationType: "CREATE",
			GroupKey: groupKey,
		})
	}
	batch := queue.Drain()
	if len(batch.groups) != 1 || len(batch.users) != 0 || batch.globalRepair {
		t.Fatalf("batch = %+v", batch)
	}
	if got := m.EventHintsCoalesced.Load(); got != 9_999 {
		t.Fatalf("coalesced hints = %d, want 9999", got)
	}
}

func TestEventQueueFallsBackToOneBoundedRepairOnDistinctKeyOverflow(t *testing.T) {
	m := &metrics.Metrics{}
	queue := newEventQueue(m)
	defer queue.Close()
	for index := 0; index <= maxDirtyRoutes; index++ {
		queue.Add(webhook.Hint{
			ResourceType: "GROUP", OperationType: "UPDATE",
			GroupKey: fmt.Sprintf("%064x", index),
		})
	}
	batch := queue.Drain()
	if !batch.globalRepair || len(batch.groups) != 0 || len(batch.users) != 0 {
		t.Fatalf("overflow batch = %+v", batch)
	}
}
