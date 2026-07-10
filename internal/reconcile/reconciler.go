// Package reconcile converts current source state into provider sync requests.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/enel1221/GroupBridge/internal/config"
	"github.com/enel1221/GroupBridge/internal/metrics"
	"github.com/enel1221/GroupBridge/internal/model"
	"github.com/enel1221/GroupBridge/internal/provider"
	"github.com/enel1221/GroupBridge/internal/source"
	"github.com/enel1221/GroupBridge/internal/state"
)

type Reconciler struct {
	source    source.Source
	providers *provider.Registry
	rules     []config.Rule
	metrics   *metrics.Metrics
	logger    *slog.Logger
	state     *state.Store
	mu        sync.Mutex
	onReady   func()
	readyOnce sync.Once
}

func New(src source.Source, providers *provider.Registry, rules []config.Rule, stateStore *state.Store, metrics *metrics.Metrics, logger *slog.Logger, onReady func()) *Reconciler {
	return &Reconciler{source: src, providers: providers, rules: rules, state: stateStore, metrics: metrics, logger: logger, onReady: onReady}
}

func (r *Reconciler) Run(ctx context.Context, interval time.Duration, triggers <-chan struct{}, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error("reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
		case <-triggers:
			// Coalesce bursts. The snapshot, not the event payload, determines changes.
			timer := time.NewTimer(300 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-stop:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

func (r *Reconciler) RunOnce(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	started := time.Now()
	groups, err := r.source.ListGroups(ctx)
	if err != nil {
		r.metrics.ReconcileErrors.Add(1)
		return fmt.Errorf("read complete Keycloak snapshot: %w", err)
	}

	type job struct {
		provider  provider.Provider
		request   model.SyncRequest
		tombstone *state.GroupMapping
	}
	jobs := make([]job, 0)
	targetOwners := make(map[string]string)
	presentSources := make(map[string]struct{})
	mappings := r.state.GroupMappings()
	var buildErrs []error
	for _, group := range groups {
		for _, rule := range r.rules {
			relative, matches := relativeGroupPath(group.Path, rule.SourceGroupPrefix)
			if !matches {
				continue
			}
			targetPath, pathErr := targetGroupPath(rule.TargetParent, relative)
			if pathErr != nil {
				buildErrs = append(buildErrs, fmt.Errorf("rule %q group %q: %w", rule.Name, group.Path, pathErr))
				continue
			}
			for _, mapping := range mappings {
				if mapping.Rule == rule.Name && mapping.SourceGroupID == group.ID && strings.HasPrefix(mapping.Provider, rule.TargetProvider+"@") && mapping.TargetGroupPath != targetPath {
					// Stable source identity owns the established target. A Keycloak
					// rename updates display metadata but never retargets access.
					targetPath = mapping.TargetGroupPath
				}
			}
			p, ok := r.providers.Get(rule.TargetProvider)
			if !ok {
				buildErrs = append(buildErrs, fmt.Errorf("rule %q target %q is unavailable", rule.Name, rule.TargetProvider))
				continue
			}
			key := rule.TargetProvider + "\x00" + targetPath
			if owner, exists := targetOwners[key]; exists {
				buildErrs = append(buildErrs, fmt.Errorf("duplicate target mapping: %q and source group %q both map to %q", owner, group.ID, targetPath))
				continue
			}
			targetOwners[key] = rule.Name + "/" + group.ID
			presentSources[rule.Name+"\x00"+group.ID] = struct{}{}
			jobs = append(jobs, job{provider: p, request: model.SyncRequest{
				RuleName: rule.Name, SourceGroup: group, TargetPath: targetPath,
				TargetParent: rule.TargetParent, CreateGroup: rule.CreateGroups, AdoptExistingGroup: rule.AdoptExistingGroup,
				AccessLevel: rule.AccessLevel, Prune: rule.Prune,
				ProtectedUsers: rule.ProtectedUsers, MaxRemovals: rule.MaxRemovals,
				IdentityMatch: rule.IdentityMatch, EnforceAccessLevel: rule.EnforceAccessLevel,
			}})
		}
	}
	// A complete source snapshot also reconciles tombstones. This is how a
	// deleted group, or one moved outside a configured prefix, gives up access.
	for _, mapping := range mappings {
		if _, present := presentSources[mapping.Rule+"\x00"+mapping.SourceGroupID]; present {
			continue
		}
		for _, rule := range r.rules {
			if rule.Name != mapping.Rule || !strings.HasPrefix(mapping.Provider, rule.TargetProvider+"@") {
				continue
			}
			p, ok := r.providers.Get(rule.TargetProvider)
			if !ok {
				continue
			}
			key := rule.TargetProvider + "\x00" + mapping.TargetGroupPath
			if owner, exists := targetOwners[key]; exists {
				buildErrs = append(buildErrs, fmt.Errorf("tombstone target collision: %q already claims %q", owner, mapping.TargetGroupPath))
				continue
			}
			targetOwners[key] = "tombstone/" + mapping.SourceGroupID
			mappingCopy := mapping
			jobs = append(jobs, job{provider: p, tombstone: &mappingCopy, request: model.SyncRequest{
				RuleName:    rule.Name,
				SourceGroup: model.Group{ID: mapping.SourceGroupID, Path: mapping.SourceGroupPath},
				TargetPath:  mapping.TargetGroupPath, TargetParent: rule.TargetParent,
				CreateGroup: false, AdoptExistingGroup: rule.AdoptExistingGroup,
				AccessLevel: rule.AccessLevel, Prune: rule.Prune,
				ProtectedUsers: rule.ProtectedUsers, MaxRemovals: rule.MaxRemovals,
				IdentityMatch: rule.IdentityMatch, EnforceAccessLevel: rule.EnforceAccessLevel,
			}})
		}
	}
	if len(buildErrs) > 0 {
		r.metrics.ReconcileErrors.Add(1)
		return errors.Join(buildErrs...)
	}
	var applyErrs []error
	for _, job := range jobs {
		result, syncErr := job.provider.SyncGroup(ctx, job.request)
		if syncErr != nil {
			applyErrs = append(applyErrs, fmt.Errorf("sync %q with rule %q: %w", job.request.SourceGroup.Path, job.request.RuleName, syncErr))
			continue
		}
		if job.tombstone != nil && result.Converged {
			if deleteErr := r.state.DeleteGroup(job.tombstone.Provider, job.tombstone.Rule, job.tombstone.SourceGroupID); deleteErr != nil {
				applyErrs = append(applyErrs, fmt.Errorf("retire reconciled source-group tombstone: %w", deleteErr))
				continue
			}
		}
		if result.CreatedGroup {
			r.metrics.GroupsCreated.Add(1)
		}
		r.metrics.MembershipsAdded.Add(uint64(result.Added))
		r.metrics.MembershipsChanged.Add(uint64(result.Updated))
		r.metrics.MembershipsRemoved.Add(uint64(result.Removed))
		r.metrics.UnresolvedUsers.Add(uint64(result.Unresolved))
		r.logger.Info("group reconciled",
			"provider", result.Provider, "source_group", result.SourceGroup, "target_group", result.TargetGroup,
			"created_group", result.CreatedGroup, "added", result.Added, "updated", result.Updated,
			"removed", result.Removed, "unresolved", result.Unresolved, "protected", result.SkippedRemoval,
			"duration", result.Duration)
	}
	r.metrics.Reconciles.Add(1)
	if len(applyErrs) > 0 {
		r.metrics.ReconcileErrors.Add(1)
		return errors.Join(applyErrs...)
	}
	r.logger.Info("reconciliation complete", "source_groups", len(groups), "jobs", len(jobs), "duration", time.Since(started))
	if r.onReady != nil {
		r.readyOnce.Do(r.onReady)
	}
	return nil
}

func relativeGroupPath(groupPath, prefix string) (string, bool) {
	groupPath = "/" + strings.Trim(groupPath, "/")
	prefix = "/" + strings.Trim(prefix, "/")
	if prefix == "/" {
		return strings.Trim(groupPath, "/"), groupPath != "/"
	}
	if groupPath == prefix {
		return "", false // the prefix is a namespace boundary, not a managed group
	}
	if !strings.HasPrefix(groupPath, prefix+"/") {
		return "", false
	}
	return strings.TrimPrefix(groupPath, prefix+"/"), true
}

var unsafePathChars = regexp.MustCompile(`[^a-z0-9_-]+`)

func targetGroupPath(parent, relative string) (string, error) {
	var mapped []string
	for _, segment := range strings.Split(strings.Trim(relative, "/"), "/") {
		slug := strings.Trim(unsafePathChars.ReplaceAllString(strings.ToLower(segment), "-"), "-_")
		if slug == "" {
			return "", fmt.Errorf("group path segment %q has no GitLab-safe characters", segment)
		}
		mapped = append(mapped, slug)
	}
	parts := []string{strings.Trim(parent, "/"), strings.Join(mapped, "/")}
	return strings.Trim(strings.Join(parts, "/"), "/"), nil
}
