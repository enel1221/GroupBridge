// Package metrics provides dependency-free Prometheus text metrics.
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
)

type Metrics struct {
	Reconciles         atomic.Uint64
	ReconcileErrors    atomic.Uint64
	WebhookAccepted    atomic.Uint64
	WebhookRejected    atomic.Uint64
	GroupsCreated      atomic.Uint64
	MembershipsAdded   atomic.Uint64
	MembershipsChanged atomic.Uint64
	MembershipsRemoved atomic.Uint64
	UnresolvedUsers    atomic.Uint64
}

func (m *Metrics) WritePrometheus(w io.Writer) {
	write := func(name, help string, value uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
	}
	write("groupbridge_reconciles_total", "Completed reconciliation scans.", m.Reconciles.Load())
	write("groupbridge_reconcile_errors_total", "Reconciliation scans that returned an error.", m.ReconcileErrors.Load())
	write("groupbridge_webhook_accepted_total", "Authenticated Keycloak hints accepted.", m.WebhookAccepted.Load())
	write("groupbridge_webhook_rejected_total", "Keycloak hints rejected.", m.WebhookRejected.Load())
	write("groupbridge_groups_created_total", "Target groups created.", m.GroupsCreated.Load())
	write("groupbridge_memberships_added_total", "Target memberships added.", m.MembershipsAdded.Load())
	write("groupbridge_memberships_changed_total", "Target membership access levels changed.", m.MembershipsChanged.Load())
	write("groupbridge_memberships_removed_total", "Target memberships removed.", m.MembershipsRemoved.Load())
	write("groupbridge_unresolved_users_total", "Source users not yet resolvable at a target.", m.UnresolvedUsers.Load())
}
