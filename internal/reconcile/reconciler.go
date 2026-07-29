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
	if err := r.migrateCanonicalMappings(groups); err != nil {
		r.metrics.ReconcileErrors.Add(1)
		return fmt.Errorf("migrate GitOps-declared canonical source mappings: %w", err)
	}

	type job struct {
		groupProvider  provider.GroupSyncProvider
		accessProvider provider.AccessProvider
		groupRequest   model.SyncRequest
		accessRequest  model.AccessSyncRequest
		tombstone      *state.GroupMapping
	}
	jobs := make([]job, 0)
	targetOwners := make(map[string]string)
	presentSources := make(map[string]struct{})
	mappings := r.state.GroupMappings()
	var buildErrs []error
	for _, group := range groups {
		for _, rule := range r.rules {
			relative, matches := relativeGroupPath(group.Path, rule.SourceGroupPrefix)
			if !matches || !sourcePathAllowed(rule, group.Path) {
				continue
			}
			sourceKey := sourceStateKey(rule, group)
			parent := rule.TargetParent
			if rule.Vault != nil {
				parent = rule.Vault.PathPrefix
			}
			var targetPath string
			var pathErr error
			if rule.Vault != nil {
				targetPath, pathErr = vaultSecretPath(parent, relative)
			} else {
				targetPath, pathErr = targetGroupPath(parent, relative)
			}
			if pathErr != nil {
				buildErrs = append(buildErrs, fmt.Errorf("rule %q group %q: %w", rule.Name, group.Path, pathErr))
				continue
			}
			for _, mapping := range mappings {
				if rule.Vault == nil && mapping.Rule == rule.Name && mapping.SourceGroupID == sourceKey && strings.HasPrefix(mapping.Provider, rule.TargetProvider+"@") && mapping.TargetGroupPath != targetPath {
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
			presentSources[rule.Name+"\x00"+sourceKey] = struct{}{}
			if rule.Vault != nil {
				ap, supported := p.(provider.AccessProvider)
				if !supported {
					buildErrs = append(buildErrs, fmt.Errorf("rule %q target %q does not support access synchronization", rule.Name, rule.TargetProvider))
					continue
				}
				accessGroup := group
				// Vault resolves the direct Keycloak full-path group claim at
				// login; GroupBridge never provisions target users.
				accessGroup.Members = nil
				jobs = append(jobs, job{accessProvider: ap, accessRequest: model.AccessSyncRequest{
					RuleName: rule.Name, StateKey: sourceKey, SourceGroup: accessGroup,
					SecretPath: targetPath, AccessProfile: rule.Vault.AccessProfile,
					PolicyMode: vaultPolicyMode(rule), Discoverable: rule.Vault.Discoverable,
				}})
			} else {
				gp, supported := p.(provider.GroupSyncProvider)
				if !supported {
					buildErrs = append(buildErrs, fmt.Errorf("rule %q target %q does not support membership synchronization", rule.Name, rule.TargetProvider))
					continue
				}
				jobs = append(jobs, job{groupProvider: gp, groupRequest: model.SyncRequest{
					RuleName: rule.Name, StateKey: sourceKey, SourceGroup: group, TargetPath: targetPath,
					TargetParent: rule.TargetParent, CreateGroup: rule.CreateGroups, AdoptExistingGroup: rule.AdoptExistingGroup,
					AccessLevel: rule.AccessLevel, Prune: rule.Prune,
					ProtectedUsers: rule.ProtectedUsers, MaxRemovals: rule.MaxRemovals,
					IdentityMatch: rule.IdentityMatch, EnforceAccessLevel: rule.EnforceAccessLevel,
				}})
			}
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
			// Vault groups, aliases, and policies are GitOps-owned VCO
			// resources. GroupBridge has no Vault lifecycle ledger to retire.
			if rule.Vault != nil {
				continue
			}
			// An exact GitOps allowlist distinguishes a temporary Keycloak
			// rebuild from intentional org removal. Listed-but-absent paths hold
			// their access mapping until the group returns with a new UUID.
			if rule.SourceGroupPaths != nil && sourcePathAllowed(rule, mapping.SourceGroupPath) {
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
			gp, supported := p.(provider.GroupSyncProvider)
			if !supported {
				buildErrs = append(buildErrs, fmt.Errorf("rule %q target %q does not support membership synchronization", rule.Name, rule.TargetProvider))
				continue
			}
			jobs = append(jobs, job{groupProvider: gp, tombstone: &mappingCopy, groupRequest: model.SyncRequest{
				RuleName: rule.Name, StateKey: mapping.SourceGroupID,
				SourceGroup: model.Group{ID: sourceNativeID(mapping), Path: mapping.SourceGroupPath},
				TargetPath:  mapping.TargetGroupPath, TargetParent: rule.TargetParent,
				CreateGroup: false, AdoptExistingGroup: rule.AdoptExistingGroup,
				AccessLevel: rule.AccessLevel, Prune: rule.Prune,
				ProtectedUsers: rule.ProtectedUsers, MaxRemovals: rule.MaxRemovals,
				IdentityMatch: rule.IdentityMatch, EnforceAccessLevel: rule.EnforceAccessLevel,
				ImmediateRemoval: rule.SourceGroupPaths != nil,
			}})
		}
	}
	if len(buildErrs) > 0 {
		r.metrics.ReconcileErrors.Add(1)
		return errors.Join(buildErrs...)
	}
	var healthErrs []error
	for _, targetProvider := range r.providers.All() {
		if healthErr := targetProvider.HealthCheck(ctx); healthErr != nil {
			r.metrics.ProviderHealthErrors.Add(1)
			healthErrs = append(healthErrs, fmt.Errorf("provider %q health check: %w", targetProvider.Name(), healthErr))
		}
	}
	if len(healthErrs) > 0 {
		r.metrics.ReconcileErrors.Add(1)
		return errors.Join(healthErrs...)
	}
	var applyErrs []error
	for _, job := range jobs {
		if job.accessProvider != nil {
			result, syncErr := job.accessProvider.SyncAccessGroup(ctx, job.accessRequest)
			if syncErr != nil {
				applyErrs = append(applyErrs, fmt.Errorf("sync access for %q with rule %q: %w", job.accessRequest.SourceGroup.Path, job.accessRequest.RuleName, syncErr))
				continue
			}
			if result.VerifiedPolicy {
				r.metrics.AccessPoliciesVerified.Add(1)
			}
			r.logger.Info("access group reconciled",
				"provider", result.Provider, "source_group", result.SourceGroup, "secret_path", result.SecretPath,
				"verified_policy", result.VerifiedPolicy, "duration", result.Duration)
			continue
		}
		result, syncErr := job.groupProvider.SyncGroup(ctx, job.groupRequest)
		if syncErr != nil {
			applyErrs = append(applyErrs, fmt.Errorf("sync %q with rule %q: %w", job.groupRequest.SourceGroup.Path, job.groupRequest.RuleName, syncErr))
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

func (r *Reconciler) migrateCanonicalMappings(groups []model.Group) error {
	mappings := r.state.GroupMappings()
	for _, rule := range r.rules {
		// Only direct-membership providers own state mappings. VCO owns the
		// complete Vault object lifecycle, so a Vault rule must not migrate or
		// create ledger entries.
		if rule.Vault != nil || rule.SourceGroupPaths == nil {
			continue
		}
		for _, group := range groups {
			if !sourcePathAllowed(rule, group.Path) {
				continue
			}
			for _, mapping := range mappings {
				if mapping.Rule != rule.Name ||
					!strings.HasPrefix(mapping.Provider, rule.TargetProvider+"@") ||
					mapping.SourceGroupPath != group.Path ||
					mapping.SourceGroupID == group.Path {
					continue
				}
				if err := r.state.MoveGroup(mapping.Provider, mapping.Rule, mapping.SourceGroupID, group.Path, group.ID, group.Path); err != nil {
					return fmt.Errorf("move rule %q path %q from legacy key %q: %w", rule.Name, group.Path, mapping.SourceGroupID, err)
				}
			}
		}
	}
	return nil
}

func vaultPolicyMode(rule config.Rule) string {
	if rule.Vault == nil || rule.Vault.PolicyMode == "" {
		return "verify-only"
	}
	return rule.Vault.PolicyMode
}

func sourceStateKey(rule config.Rule, group model.Group) string {
	if rule.Vault != nil || rule.SourceGroupPaths != nil {
		return group.Path
	}
	return group.ID
}

func sourcePathAllowed(rule config.Rule, path string) bool {
	if rule.SourceGroupPaths == nil {
		return true
	}
	for _, allowed := range rule.SourceGroupPaths {
		if path == allowed {
			return true
		}
	}
	return false
}

func sourceNativeID(mapping state.GroupMapping) string {
	if mapping.SourceNativeID != "" {
		return mapping.SourceNativeID
	}
	return mapping.SourceGroupID
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

var vaultPathSegment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

func vaultSecretPath(parent, relative string) (string, error) {
	parts := make([]string, 0)
	for _, raw := range []string{strings.Trim(parent, "/"), strings.Trim(relative, "/")} {
		if raw == "" {
			continue
		}
		for _, segment := range strings.Split(raw, "/") {
			if !vaultPathSegment.MatchString(segment) || segment == "." || segment == ".." {
				return "", fmt.Errorf("Vault path segment %q must contain 1-63 ASCII letters, digits, hyphens, or underscores", segment)
			}
			parts = append(parts, strings.ToLower(segment))
		}
	}
	result := strings.Join(parts, "/")
	if result == "" || len(result) > 240 {
		return "", errors.New("Vault secret path must contain 1-240 safe characters")
	}
	return result, nil
}
