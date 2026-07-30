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
	secret  secretLoader
	maxSkew time.Duration
	realm   string
	now     func() time.Time
	trigger func(Hint)
	metrics *metrics.Metrics

	mu   sync.Mutex
	seen map[string]time.Time
}

type secretLoader interface {
	Load() (string, error)
}

// Hint contains only the event classification needed to schedule a fresh
// source read. It is never used as desired-state or identity data.
type Hint struct {
	ResourceType  string
	OperationType string
	GroupKey      string
	UserKey       string
	GlobalRepair  bool
}

type envelope struct {
	SpecVersion   string `json:"specVersion"`
	EventID       string `json:"eventId"`
	OccurredAt    string `json:"occurredAt"`
	RealmName     string `json:"realmName"`
	ResourceType  string `json:"resourceType"`
	OperationType string `json:"operationType"`
	GroupKey      string `json:"groupKey"`
	UserKey       string `json:"userKey"`
}

func New(secret secretLoader, realm string, maxSkew time.Duration, trigger func(Hint), metrics *metrics.Metrics) *Handler {
	return &Handler{secret: secret, realm: realm, maxSkew: maxSkew, now: time.Now, trigger: trigger, metrics: metrics, seen: make(map[string]time.Time)}
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
	if err != nil || delivery == "" || len(delivery) > 128 || !h.fresh(time.Unix(seconds, 0)) {
		h.reject(w)
		return
	}
	secret, err := h.secret.Load()
	if err != nil || len([]byte(secret)) < 32 ||
		!validSignature([]byte(secret), timestamp, delivery, body, signature) {
		h.reject(w)
		return
	}
	var event envelope
	if err := json.Unmarshal(body, &event); err != nil || event.SpecVersion != "1.0" ||
		event.EventID == "" || event.EventID != delivery || event.RealmName != h.realm {
		h.reject(w)
		return
	}
	hint, valid := classify(event)
	if !valid {
		h.reject(w)
		return
	}
	if h.replayed(delivery) {
		h.reject(w)
		return
	}
	h.metrics.WebhookAccepted.Add(1)
	h.trigger(hint)
	w.WriteHeader(http.StatusAccepted)
}

func classify(event envelope) (Hint, bool) {
	hint := Hint{ResourceType: event.ResourceType, OperationType: event.OperationType}
	switch event.ResourceType {
	case "GROUP":
		if event.OperationType != "CREATE" && event.OperationType != "UPDATE" && event.OperationType != "DELETE" {
			return Hint{}, false
		}
		if event.UserKey != "" {
			return Hint{}, false
		}
		hint.GroupKey = event.GroupKey
	case "GROUP_MEMBERSHIP":
		if event.OperationType != "CREATE" && event.OperationType != "DELETE" {
			return Hint{}, false
		}
		if event.UserKey != "" {
			return Hint{}, false
		}
		hint.GroupKey = event.GroupKey
	case "USER":
		switch event.OperationType {
		case "LOGIN":
			if event.GroupKey != "" {
				return Hint{}, false
			}
			hint.UserKey = event.UserKey
		case "CREATE":
			if event.UserKey != "" {
				return Hint{}, false
			}
			hint.GroupKey = event.GroupKey
		case "UPDATE":
			if event.GroupKey != "" {
				return Hint{}, false
			}
			hint.UserKey = event.UserKey
		case "DELETE":
			if (event.GroupKey == "") == (event.UserKey == "") {
				if event.GroupKey != "" {
					return Hint{}, false
				}
				hint.GlobalRepair = true
				return hint, true
			}
			hint.GroupKey = event.GroupKey
			hint.UserKey = event.UserKey
		default:
			return Hint{}, false
		}
	default:
		return Hint{}, false
	}
	if hint.GroupKey == "" && hint.UserKey == "" {
		hint.GlobalRepair = true
		return hint, true
	}
	if (hint.GroupKey != "" && !validRoutingKey(hint.GroupKey)) ||
		(hint.UserKey != "" && !validRoutingKey(hint.UserKey)) {
		return Hint{}, false
	}
	return hint, true
}

func validRoutingKey(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validSignature(secret []byte, timestamp, delivery string, body []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
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
