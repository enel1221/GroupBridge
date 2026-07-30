package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/enel1221/GroupBridge/internal/metrics"
)

const testWebhookSecret = "0123456789abcdef0123456789abcdef"

type staticSecret string

func (s staticSecret) Load() (string, error) { return string(s), nil }

type rotatingSecret struct{ value string }

func (s *rotatingSecret) Load() (string, error) { return s.value, nil }

func TestHandlerAcceptsSignedHintAndRejectsReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	called := 0
	var got Hint
	h := New(staticSecret(testWebhookSecret), "demo", 5*time.Minute, func(hint Hint) {
		called++
		got = hint
	}, &metrics.Metrics{})
	h.now = func() time.Time { return now }
	body := []byte(`{"specVersion":"1.0","eventId":"delivery-1","occurredAt":"2026-01-01T00:00:00Z","realmName":"demo","resourceType":"GROUP_MEMBERSHIP","operationType":"CREATE","groupKey":"992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0","userKey":null}`)
	req := signedRequest(t, now, "delivery-1", body, testWebhookSecret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || called != 1 {
		t.Fatalf("status=%d called=%d", w.Code, called)
	}
	if got.ResourceType != "GROUP_MEMBERSHIP" || got.OperationType != "CREATE" ||
		got.GroupKey != "992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0" {
		t.Fatalf("hint = %+v", got)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, now, "delivery-1", body, testWebhookSecret))
	if w.Code != http.StatusUnauthorized || called != 1 {
		t.Fatalf("replay status=%d called=%d", w.Code, called)
	}
}

func TestHandlerRejectsStaleOrTamperedHint(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := New(staticSecret(testWebhookSecret), "demo", time.Minute, func(Hint) { t.Fatal("trigger called") }, &metrics.Metrics{})
	h.now = func() time.Time { return now }
	body := []byte(`{"specVersion":"1.0","eventId":"d","realmName":"demo","resourceType":"GROUP","operationType":"UPDATE","groupKey":"992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0"}`)
	for name, req := range map[string]*http.Request{
		"stale":    signedRequest(t, now.Add(-2*time.Minute), "d", body, testWebhookSecret),
		"tampered": signedRequest(t, now, "d", append(body, ' '), "wrong"),
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

func TestHandlerRoutesLoginAndFailsSafeToGlobalRepair(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var got []Hint
	h := New(staticSecret(testWebhookSecret), "demo", time.Minute, func(hint Hint) { got = append(got, hint) }, &metrics.Metrics{})
	h.now = func() time.Time { return now }
	bodies := [][]byte{
		[]byte(`{"specVersion":"1.0","eventId":"login","realmName":"demo","resourceType":"USER","operationType":"LOGIN","userKey":"1ac5504a72c4b71c8377044145d8f48ec91bc9141188eef45794140332277008"}`),
		[]byte(`{"specVersion":"1.0","eventId":"repair","realmName":"demo","resourceType":"GROUP","operationType":"CREATE","groupKey":null}`),
	}
	for index, body := range bodies {
		delivery := []string{"login", "repair"}[index]
		w := httptest.NewRecorder()
		h.ServeHTTP(w, signedRequest(t, now, delivery, body, testWebhookSecret))
		if w.Code != http.StatusAccepted {
			t.Fatalf("event %d status = %d", index, w.Code)
		}
	}
	if len(got) != 2 || got[0].UserKey == "" || !got[1].GlobalRepair {
		t.Fatalf("hints = %+v", got)
	}
}

func TestHandlerRejectsUnsafeOrAmbiguousRoutingKeys(t *testing.T) {
	for name, body := range map[string][]byte{
		"uppercase":  []byte(`{"specVersion":"1.0","eventId":"d","realmName":"demo","resourceType":"GROUP","operationType":"UPDATE","groupKey":"992EADA7C9836EE842F75DC1AB1D9CF872E61BB5D6536A87C2BB52CAB6A8A8A0"}`),
		"short":      []byte(`{"specVersion":"1.0","eventId":"d","realmName":"demo","resourceType":"GROUP","operationType":"UPDATE","groupKey":"abc"}`),
		"both":       []byte(`{"specVersion":"1.0","eventId":"d","realmName":"demo","resourceType":"USER","operationType":"LOGIN","groupKey":"992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0","userKey":"1ac5504a72c4b71c8377044145d8f48ec91bc9141188eef45794140332277008"}`),
		"wrong-op":   []byte(`{"specVersion":"1.0","eventId":"d","realmName":"demo","resourceType":"GROUP_MEMBERSHIP","operationType":"UPDATE","groupKey":null}`),
		"wrong-type": []byte(`{"specVersion":"1.0","eventId":"d","realmName":"demo","resourceType":"CLIENT","operationType":"UPDATE","groupKey":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			h := New(staticSecret(testWebhookSecret), "demo", time.Minute, func(Hint) { t.Fatal("trigger called") }, &metrics.Metrics{})
			h.now = func() time.Time { return now }
			w := httptest.NewRecorder()
			h.ServeHTTP(w, signedRequest(t, now, "d", body, testWebhookSecret))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d", w.Code)
			}
		})
	}
}

func TestHandlerReloadsRotatedWebhookSecret(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	first := testWebhookSecret
	second := "abcdef0123456789abcdef0123456789"
	secret := &rotatingSecret{value: first}
	called := 0
	h := New(secret, "demo", time.Minute, func(Hint) { called++ }, &metrics.Metrics{})
	h.now = func() time.Time { return now }
	body := []byte(`{"specVersion":"1.0","eventId":"first","realmName":"demo","resourceType":"GROUP","operationType":"UPDATE","groupKey":"992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0"}`)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, now, "first", body, first))
	if w.Code != http.StatusAccepted {
		t.Fatalf("first status = %d", w.Code)
	}

	secret.value = second
	body = []byte(`{"specVersion":"1.0","eventId":"second","realmName":"demo","resourceType":"GROUP","operationType":"UPDATE","groupKey":"992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0"}`)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, now, "second", body, second))
	if w.Code != http.StatusAccepted || called != 2 {
		t.Fatalf("rotated status = %d, called = %d", w.Code, called)
	}
}

func TestClassifyDistinguishesDirectUserRevocationFromMembershipFallback(t *testing.T) {
	userKey := "1ac5504a72c4b71c8377044145d8f48ec91bc9141188eef45794140332277008"
	groupKey := "992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0"
	direct, valid := classify(envelope{
		ResourceType: "USER", OperationType: "DELETE", UserKey: userKey,
	})
	if !valid || direct.UserKey != userKey || direct.GroupKey != "" {
		t.Fatalf("direct user hint = %+v, valid = %t", direct, valid)
	}
	membership, valid := classify(envelope{
		ResourceType: "USER", OperationType: "DELETE", GroupKey: groupKey,
	})
	if !valid || membership.GroupKey != groupKey || membership.UserKey != "" {
		t.Fatalf("membership fallback hint = %+v, valid = %t", membership, valid)
	}
	update, valid := classify(envelope{
		ResourceType: "USER", OperationType: "UPDATE", UserKey: userKey,
	})
	if !valid || update.UserKey != userKey {
		t.Fatalf("direct user update = %+v, valid = %t", update, valid)
	}
}

func signedRequest(t *testing.T, at time.Time, delivery string, body []byte, secret string) *http.Request {
	t.Helper()
	timestamp := fmt.Sprintf("%d", at.Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "\n" + delivery + "\n"))
	mac.Write(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/events/keycloak", bytes.NewReader(body))
	req.Header.Set("X-GroupBridge-Timestamp", timestamp)
	req.Header.Set("X-GroupBridge-Delivery", delivery)
	req.Header.Set("X-GroupBridge-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return req
}
