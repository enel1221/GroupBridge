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

func TestHandlerAcceptsSignedHintAndRejectsReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	called := 0
	h := New("secret", "demo", 5*time.Minute, func() { called++ }, &metrics.Metrics{})
	h.now = func() time.Time { return now }
	body := []byte(`{"specVersion":"1.0","eventId":"delivery-1","occurredAt":"2026-01-01T00:00:00Z","realmId":"r","realmName":"demo","resourceType":"GROUP_MEMBERSHIP","operationType":"CREATE","resourcePath":"users/u/groups/g","resourceId":"g"}`)
	req := signedRequest(t, now, "delivery-1", body, "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || called != 1 {
		t.Fatalf("status=%d called=%d", w.Code, called)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, now, "delivery-1", body, "secret"))
	if w.Code != http.StatusUnauthorized || called != 1 {
		t.Fatalf("replay status=%d called=%d", w.Code, called)
	}
}

func TestHandlerRejectsStaleOrTamperedHint(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := New("secret", "demo", time.Minute, func() { t.Fatal("trigger called") }, &metrics.Metrics{})
	h.now = func() time.Time { return now }
	body := []byte(`{"specVersion":"1.0","eventId":"d","realmId":"r","realmName":"demo","resourceType":"GROUP","operationType":"UPDATE"}`)
	for name, req := range map[string]*http.Request{
		"stale":    signedRequest(t, now.Add(-2*time.Minute), "d", body, "secret"),
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
