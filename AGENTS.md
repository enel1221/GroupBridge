# Agent guide

These instructions apply to the entire repository.

## Before changing code

Read `README.md`, `docs/architecture.md`, and `SECURITY.md`. If working in the Keycloak
extension, also read `extensions/keycloak-event-listener/README.md` completely.

## Required invariants

- Events are hints; reconcile from a complete source snapshot.
- Do not prune after any incomplete/pagination/source read.
- Never delete GitLab groups, Owners, the API identity, protected users, or custom-role
  users.
- Direct membership deletion must retain `skip_subresources=true` and
  `unassign_issuables=false`.
- Do not add desired Owner/Admin support.
- Never print credentials, PII-bearing API bodies, or secret environment values.
- Keep the controller usable with no Kubernetes API access.
- Keep Java limited to the listener subtree and dependency-free at runtime.

## Validation

Run `make verify`. Provider work also needs focused tests for pagination, safety gates,
and exact outbound API semantics. Helm changes require `helm lint` and rendered-manifest
inspection. Demo changes should be exercised with `make demo-up` and cleaned with
`make demo-down`.

Use `apply_patch` for edits, preserve unrelated user changes, and do not commit generated
credentials, kubeconfigs, build artifacts, or `.groupbridge/`.
