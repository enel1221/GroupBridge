// Package webhook verifies Keycloak event hints. Hints only trigger a fresh read.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/enel1221/GroupBridge/internal/metrics"
)

const maxBodyBytes = 64 << 10

type Handler struct {
	secret  []byte
	maxSkew time.Duration
	realm   string
	now     func() time.Time
	trigger func()
	metrics *metrics.Metrics

	mu   sync.Mutex
	seen map[string]time.Time
}

type envelope struct {
	SpecVersion   string `json:"specVersion"`
	EventID       string `json:"eventId"`
	OccurredAt    string `json:"occurredAt"`
	RealmID       string `json:"realmId"`
	RealmName     string `json:"realmName"`
	ResourceType  string `json:"resourceType"`
	OperationType string `json:"operationType"`
	ResourcePath  string `json:"resourcePath"`
	ResourceID    string `json:"resourceId"`
}

func New(secret, realm string, maxSkew time.Duration, trigger func(), metrics *metrics.Metrics) *Handler {
	return &Handler{secret: []byte(secret), realm: realm, maxSkew: maxSkew, now: time.Now, trigger: trigger, metrics: metrics, seen: make(map[string]time.Time)}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.reject(w)
		return
	}
	timestamp := r.Header.Get("X-GroupBridge-Timestamp")
	delivery := r.Header.Get("X-GroupBridge-Delivery")
	signature := r.Header.Get("X-GroupBridge-Signature")
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || delivery == "" || len(delivery) > 128 || !h.fresh(time.Unix(seconds, 0)) || !h.validSignature(timestamp, delivery, body, signature) {
		h.reject(w)
		return
	}
	var event envelope
	if err := json.Unmarshal(body, &event); err != nil || event.SpecVersion != "1.0" || event.EventID == "" || event.EventID != delivery || event.RealmID == "" || event.RealmName != h.realm || event.ResourceType == "" || event.OperationType == "" {
		h.reject(w)
		return
	}
	if h.replayed(delivery) {
		h.reject(w)
		return
	}
	h.metrics.WebhookAccepted.Add(1)
	h.trigger()
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) validSignature(timestamp, delivery string, body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(delivery))
	mac.Write([]byte{'\n'})
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func (h *Handler) fresh(t time.Time) bool {
	delta := h.now().Sub(t)
	return delta <= h.maxSkew && delta >= -h.maxSkew
}

func (h *Handler) replayed(delivery string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := h.now().Add(-h.maxSkew)
	for id, seenAt := range h.seen {
		if seenAt.Before(cutoff) {
			delete(h.seen, id)
		}
	}
	if _, exists := h.seen[delivery]; exists {
		return true
	}
	if len(h.seen) >= 10_000 {
		return true
	}
	h.seen[delivery] = h.now()
	return false
}

func (h *Handler) reject(w http.ResponseWriter) {
	h.metrics.WebhookRejected.Add(1)
	http.Error(w, "invalid event", http.StatusUnauthorized)
}
