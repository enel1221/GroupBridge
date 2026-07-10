// Package app wires GroupBridge's HTTP surface and reconciliation trigger.
package app

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/enel1221/GroupBridge/internal/metrics"
)

type Server struct {
	mux     *http.ServeMux
	ready   atomic.Bool
	metrics *metrics.Metrics
}

func NewServer(webhook http.Handler, m *metrics.Metrics, version string) *Server {
	s := &Server{mux: http.NewServeMux(), metrics: m}
	s.mux.Handle("POST /v1/events/keycloak", webhook)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	s.mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m.WritePrometheus(w)
	})
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"name": "GroupBridge", "version": version})
	})
	return s
}

func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }
func (s *Server) SetReady(ready bool)   { s.ready.Store(ready) }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
