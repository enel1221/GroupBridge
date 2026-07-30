# Architecture

GroupBridge is an external desired-state controller. Keycloak is the source, rules
select source groups, and compiled-in target providers translate direct membership into
the target's native API.

```mermaid
flowchart LR
  KC["Keycloak Admin API"] -->|"exact group reads and periodic complete snapshot"| R["Go reconciler"]
  SPI["Minimal Keycloak listener"] -->|"signed hint"| WH["Webhook verifier"]
  WH -->|"private HMAC route key"| Q["Bounded keyed dirty queue"]
  Q --> R
  TIMER["Periodic repair scan"] --> R
  R -->|"desired direct membership"| GL["GitLab API"]
  R -->|"verify policies, groups, and aliases"| VAULT["Vault Identity API"]
  GIT["Git org catalog"] -->|"exact path intent and ACL policies"| R
  GIT --> VAULT
  R <--> LEDGER["Persistent ownership ledger"]
```

## Invariants

- Event bodies never authorize changes. Private HMAC routing keys select an
  authoritative Keycloak re-read; source responses and GitOps rules decide mutations.
- A failed or partial Keycloak snapshot produces no target changes.
- Additions and role increases happen before removals.
- Only direct GitLab membership is read, changed, or pruned.
- Owners, the current token user, custom-role users, and configured protected users are
  never removed or downgraded.
- Every delete disables GitLab's descendant-resource cascade.
- Group deletion is outside the v1 capability set.
- `managed-only` prune removes only ledger-owned memberships.
- A target-path collision fails before any provider mutation.
- A missing membership must be seen in two complete snapshots before deletion.
- Deleted or moved source groups are reconciled through persisted mapping tombstones.
- Exact `sourceGroupPaths` distinguish a temporary Keycloak rebuild from an intentional
  Git removal. Canonical full paths, not recreated Keycloak UUIDs, own declared targets.
- Vault reconciliation never provisions users, reads secret data, writes ACL policies,
  or deletes identity objects.

## Provider boundary

The common `provider.Provider` interface exposes only a name and health check.
`GroupSyncProvider` handles GitLab-style direct membership, while `AccessProvider`
handles Vault-style claim-backed access without target user provisioning. Providers are
compiled into the binary through an explicit registry—there is no dynamic code loading
or Go plugin ABI.

Vault ACL policies and the KV v2 mount are GitOps-owned. The provider derives the exact
expected name and HCL, then verifies the external identity group and exact Keycloak
full-path OIDC group alias that VCO/Argo created. VCO/Argo owns creation, updates, and
deletion from the same Git organization catalog; GroupBridge only verifies exact live
state.

## State and availability

The first release uses an atomically replaced JSON ownership ledger on a PVC. It is
deliberately single-writer and the chart fixes the operational model at one replica.
Webhook hints are lossy; the periodic full scan is the durability mechanism.

Authenticated event bursts are gathered for a 200 millisecond quiet window and bounded
by a two-second maximum delay. The listener sends domain-separated HMAC routing keys,
never native user/group IDs or admin resource paths. A successful full snapshot builds
the in-memory key-to-native-ID index. Known group/member hints re-read exactly one
complete group and direct-member page; LOGIN and direct USER update/delete hints fan out
only to the user's previously indexed groups. Work is serial, bounded to 10,000 distinct
dirty routes, and a key dirtied during reconciliation receives a trailing pass.

Unknown keys, including a newly created group not yet in the index, request a
rate-limited complete topology repair. The five-minute periodic snapshot remains the
durable drift-repair path. Membership removal and direct user disable/delete schedule a
second exact read after 1.5 seconds, preserving the two-observation deletion gate
without waiting for the periodic scan. Only successful logins for explicitly
allowlisted OIDC client IDs receive the three-second GitLab JIT retry. Membership-only
work skips Vault because Vault resolves group claims at login and its access objects are
GitOps-owned.

Provider credentials may be environment-backed for compatibility or file-backed for
rotation. File-backed loaders reopen the configured absolute path for every Keycloak
token request and GitLab API request. Kubernetes Secret volumes must be mounted as
directories rather than `subPath` files so kubelet's atomic symlink swap is observable.
The webhook HMAC supports the same mutually exclusive environment/file model. Its
file-backed stable loader refreshes signature verification and the private route index
without a restart while retaining the last valid value across a transient rotation.

The multi-replica design boundary is a PostgreSQL-backed dirty-key queue and ownership
store with row locking. Webhook receivers and workers can then be active-active while a
lease or database advisory lock elects one periodic scanner. That feature must land
before raising the chart replica count.

## Identity

For GitOps-declared rules, canonical full paths are durable organization identities and
Keycloak UUIDs are runtime correlation only. This permits a complete Keycloak rebuild
without embedding generated UUIDs in Git. GitLab user joins are provider-bound OIDC
external identities: preferably the immutable Keycloak user ID (`oidc`), or the exact
Keycloak username compatibility mode (`oidc-username`) when GitLab uses
`uid_field: preferred_username`. The latter cannot be combined with username/email
fallbacks, so a colliding local GitLab username cannot receive access, but it requires
an installation-level invariant that Keycloak usernames are never renamed or reused.
Vault instead maps each direct, full Keycloak group path from the dedicated
`vault_groups` claim to an external-group alias during OIDC login. Direct full paths
avoid the parent-role inheritance that would otherwise over-grant nested organizations.
