# GroupBridge

[![CI](https://github.com/enel1221/GroupBridge/actions/workflows/ci.yaml/badge.svg)](https://github.com/enel1221/GroupBridge/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)

GroupBridge is a small identity access controller that makes Keycloak group membership
the source of truth for GitLab direct membership and Vault organization access. It is written in Go, with one
optional dependency-free Keycloak Java listener for low-latency change hints.

Events make it fast; reconciliation makes it correct. Every webhook causes GroupBridge
to read current state from Keycloak before touching GitLab, and a periodic scan repairs
missed events. GitLab is the first compiled-in target provider; the internal provider
contract is intentionally small so future providers do not have to imitate GitLab.

## What works today

- discovers every Keycloak group below a configured path prefix;
- maps the hierarchy 1:1 into existing GitLab groups or creates private groups/subgroups;
- adds, raises, and safely prunes direct GitLab memberships;
- resolves users by provider-bound Keycloak OIDC subject or `preferred_username`,
  with explicit username/email compatibility modes;
- protects Owners, the GitLab API identity, custom-role users, and configured break-glass users;
- refuses removal batches above a configured circuit breaker;
- accepts timestamped, replay-protected HMAC event hints and also polls on a fixed interval;
- runs without Kubernetes API credentials in a restricted, single-replica Helm Deployment;
- verifies GitOps-owned Vault external groups and exact Keycloak full-path OIDC group aliases;
- verifies GitOps-owned, per-organization KV v2 policies and never accesses secret data;
- provides a complete Keycloak + GitLab CE + GroupBridge k3d demo.

“1:1” means direct Keycloak group membership to direct GitLab group membership. GitLab
access inherited from ancestors, invited groups, or projects is deliberately outside
that contract and is never removed by GroupBridge.

## Try the complete demo

Prerequisites: Docker, k3d, kubectl, Helm, Make, 8 GB of free memory, and roughly 30 GB
of free disk. GitLab is large and commonly takes 5–15 minutes to become ready on its
first boot.

```bash
make demo-up
```

The command detects the host LAN address, creates a k3d cluster, builds and imports both
GroupBridge images, bootstraps Keycloak and GitLab, and prints URLs and generated
credentials. To force the externally reachable address:

```bash
make demo-up HOST_IP=10.0.0.203
```

Then:

1. Open the printed Keycloak URL and sign in to the `groupbridge` realm admin console.
2. Create a group and add the printed demo user to it.
3. Open the GitLab URL and choose **Keycloak** to sign in as that user.
4. Within the five-second repair interval (normally sooner via the event listener), refresh
   GitLab and the matching private group and Developer membership will be present.

Useful commands:

```bash
make demo-status
make demo-test
kubectl -n groupbridge-demo logs deployment/groupbridge -f
kubectl -n groupbridge-demo port-forward service/groupbridge 9090:8080
curl http://127.0.0.1:9090/metrics
make demo-down
```

Generated credentials and the remote kubeconfig live under `.groupbridge/`, which is
gitignored. The demo is for local evaluation: it intentionally uses HTTP and exposes
the Kubernetes API and application ports on the LAN.

## Install into Kubernetes

Create credentials out of band. The Keycloak secret belongs to a confidential
service-account client with `realm-management/view-users`; the GitLab token needs API
access to the managed parent. A separate resolver token needs administrator read access
when OIDC `extern_uid` lookup is used.

```bash
kubectl create namespace groupbridge
kubectl -n groupbridge create secret generic groupbridge \
  --from-literal=keycloak-client-secret='<keycloak client secret>' \
  --from-literal=gitlab-token='<gitlab token>' \
  --from-literal=gitlab-resolver-token='<GitLab admin read token>' \
  --from-literal=webhook-secret="$(openssl rand -hex 32)"

helm upgrade --install groupbridge oci://ghcr.io/enel1221/charts/groupbridge \
  --namespace groupbridge \
  --version 0.1.0 \
  --set secret.existingSecret=groupbridge
```

Before the first published release, clone this repository and replace the OCI reference
with `./charts/groupbridge`. Keep `replicaCount: 1`: the v1 ownership ledger is a
single-writer file on a persistent volume. PostgreSQL-backed active-active workers are a
planned scaling feature, not something the chart pretends to support today.

The chart deliberately creates no Role or ClusterRole and disables automatic service
account token mounting. Its defaults use a read-only root filesystem, a non-root UID,
dropped Linux capabilities, RuntimeDefault seccomp, a PVC for ownership state, and a
same-namespace ingress NetworkPolicy.

## Configure existing instances

Copy [examples/config.yaml](examples/config.yaml) and change the endpoints, realm, path
prefix, managed GitLab parent, and policy. Secrets are references to environment
variables or absolute files, never values in the YAML. File references are recommended
in Kubernetes because GroupBridge reopens them when it requests a Keycloak token or
calls GitLab, so projected Secret rotation does not require a pod restart.

```yaml
source:
  type: keycloak
  baseURL: https://keycloak.example.com
  realm: engineering
  clientID: groupbridge
  clientSecretFile: /var/run/secrets/groupbridge/keycloak-client-secret
  pollInterval: 30s

targets:
  - name: gitlab-main
    type: gitlab
    baseURL: https://gitlab.example.com
    tokenFile: /var/run/secrets/groupbridge/gitlab-token
    resolverTokenFile: /var/run/secrets/groupbridge/gitlab-resolver-token
    oidcProvider: openid_connect

rules:
  - name: engineering-groups
    sourceGroupPrefix: /gitlab
    targetProvider: gitlab-main
    targetParent: platform
    createGroups: false
    adoptExistingGroup: false
    accessLevel: developer
    prune: managed-only
    protectedUsers: [root, breakglass-admin]
    maxRemovals: 10
    identityMatch: [oidc]
    enforceAccessLevel: false
```

Each provider credential must configure exactly one environment or file field:
`clientSecretEnv` or `clientSecretFile`, `tokenEnv` or `tokenFile`, and
`resolverTokenEnv` or `resolverTokenFile`. Environment-based configurations remain
supported for compatibility, but Kubernetes does not update container environment
variables when a Secret rotates.

For file-backed chart deployments, set `secret.providerCredentialsMode: files`. The
chart mounts `secret.existingSecret` at `/var/run/secrets/groupbridge` by default as a
read-only directory without `subPath`; the non-root pod reads it through the configured
`fsGroup`. The key filenames come from `secret.keys`.

Group `/gitlab/payments/developers` maps to
`platform/payments/developers`. `targetParent` must already exist; when
`createGroups: true`, GroupBridge may create only the missing descendants. An empty
parent explicitly permits top-level creation on self-managed GitLab and is unsuitable
for GitLab.com.

`sourceGroupPaths` is an optional exact GitOps intent list. When present,
GroupBridge ignores undeclared Keycloak groups and uses each canonical full path as the
durable state key. A declared path that is temporarily absent during a Keycloak rebuild
is held rather than pruned; removing the path from Git triggers immediate managed-only
GitLab membership retirement. Argo/VCO separately retires GitOps-owned Vault objects.
This is the recommended mode when one organization catalog renders Keycloak groups,
GitLab configuration, and Vault policies.

Prune modes are:

- `none`: additive only;
- `managed-only`: remove only memberships recorded as created by this installation;
- `authoritative`: make direct membership exact, except protected principals.

Use `managed-only` unless the destination groups are isolated and dedicated to
GroupBridge. Existing matching memberships are not silently adopted. Group deletion and
Owner-level desired access are not implemented.

### Keycloak

Create a confidential client with service accounts enabled, assign only
`realm-management/view-users`, and copy its client secret to the Kubernetes Secret. The
repair scan needs no user-management permission.

For sub-second hints, install the tiny listener described in
[extensions/keycloak-event-listener/README.md](extensions/keycloak-event-listener/README.md),
configure its webhook URL and the shared 32-byte secret, and add `groupbridge` to the
realm's event listeners. HTTPS is mandatory by default. The listener never sends PII,
tokens, credentials, or Keycloak representations.

### GitLab

Set `oidcProvider` to GitLab's provider name (normally `openid_connect`) and select the
strategy that exactly matches GitLab's `uid_field`:

- `oidc` for `uid_field: sub` is the strongest option because the Keycloak user ID is
  immutable; it queries
  `extern_uid=<Keycloak user ID>&provider=<name>`;
- `oidc-username` is a compatibility option for
  `uid_field: preferred_username`; it queries
  `extern_uid=<Keycloak username>&provider=<name>`.

Both strategies verify that the returned GitLab user contains the exact provider and
external UID identity. `oidc-username` must be the only configured identity strategy,
so a local GitLab account with the same username is never an implicit fallback.
However, usernames are not immutable subjects: use `oidc-username` only where Keycloak
usernames are never renamed or reused, and retire or migrate the corresponding GitLab
OIDC identity before either operation. GitLab restricts external-identity lookup to
administrators, so `resolverTokenEnv` is deliberately separate from the parent-scoped
mutation token; constrain and rotate both carefully.

The controller reads `/groups/:id/members`, not effective membership. Every deletion
sets `skip_subresources=true` and `unassign_issuables=false`, so it cannot cascade into
descendant projects or groups.

### Vault

Vault rules verify external identity groups and aliases for the configured OIDC auth
mount. The Vault client's Keycloak group-membership mapper writes each user's direct,
full Keycloak group paths to the dedicated `vault_groups` claim. GitOps maps each exact
source path (for example, `/Internal/CCMO/J6`) to a Vault external-group alias. This
avoids inherited parent-group role mappings accidentally granting a child organization
its parent's policy. Vault resolves people during OIDC login and token renewal;
GroupBridge never creates Vault entities or copies individual users.

The configured mount must already be KV v2. For a canonical secret path such as
`internal/ccmo`, GitOps must create the deterministic policy
`groupbridge-org-internal-ccmo-<first-8-hex-of-sha256("internal/ccmo")>`.
GroupBridge reads and exactly verifies that policy, external group, stable metadata,
attached policy, and full-path alias. Deterministic names identify the Vault policy and
external group; the alias name is always the exact Keycloak source path. GroupBridge
has no identity mutation, policy-write, or secret-data permission.

`viewer` permits reads; `editor` permits create, read, update, patch, and soft delete.
Both list only the exact organization metadata path and its descendants by default.
`discoverable: true` also grants list-only ancestor metadata paths so the Vault UI can
navigate to the organization. Vault LIST responses are unfiltered, so this opt-in can
expose sibling key or folder names.

Use Vault Kubernetes auth with the chart's explicit audience-scoped token:

```yaml
serviceAccount:
  automountServiceAccountToken: false
  vaultToken:
    enabled: true
    audience: vault
    mountPath: /var/run/secrets/tokens
    fileName: vault
```

The Vault role should permit only exact mount-discovery probe paths, reads of compiled
policies and external groups by deterministic name, and the exact read-like
`identity/lookup/group` operation needed to validate the OIDC alias. Explicitly deny
reads of the auth and secret-mount configuration paths. It must not permit identity
mutation, policy writes, secret data access, entity/token/auth/mount administration, or
any delete operation. Validate the read-only policy against the deployed Vault version.

## Operate and troubleshoot

```bash
kubectl -n groupbridge get pods,service,pvc
kubectl -n groupbridge logs deployment/groupbridge -f
kubectl -n groupbridge get events --sort-by=.lastTimestamp
kubectl -n groupbridge port-forward service/groupbridge 8080:8080
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/metrics
```

An `unresolved` count usually means the Keycloak user has not completed their first
GitLab OIDC login yet, or the GitLab OIDC provider/subject differs from the configured
value. GroupBridge retries on every event and poll, with one delayed retry for the OIDC
just-in-time provisioning race. Removal-limit errors are fail-closed:
inspect the source and target membership before raising `maxRemovals`.

## Develop

```bash
make test
make verify
make container
make keycloak-extension
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/architecture.md](docs/architecture.md), and
[SECURITY.md](SECURITY.md). The project is Apache-2.0 licensed.
