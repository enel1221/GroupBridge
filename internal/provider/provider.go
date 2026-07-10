// Package provider defines small, compiled-in target provider capabilities.
package provider

import (
	"context"

	"github.com/enel1221/GroupBridge/internal/model"
)

// Provider converges a single source group into its native target model.
type Provider interface {
	Name() string
	HealthCheck(context.Context) error
	SyncGroup(context.Context, model.SyncRequest) (model.Result, error)
}

// Registry keeps provider construction explicit and auditable.
type Registry struct {
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) *Registry {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, p := range providers {
		r.providers[p.Name()] = p
	}
	return r
}

func (r *Registry) Get(name string) (Provider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

func (r *Registry) All() []Provider {
	result := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}
