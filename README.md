# GroupBridge

[![CI](https://github.com/enel1221/GroupBridge/actions/workflows/ci.yaml/badge.svg)](https://github.com/enel1221/GroupBridge/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)

GroupBridge is a small identity access controller that makes Keycloak group membership
the source of truth for GitLab direct group membership. It is written in Go, with one
optional dependency-free Keycloak Java listener for low-latency change hints.

Events make it fast; reconciliation makes it correct. Every webhook causes GroupBridge
to read current state from Keycloak before touching GitLab, and a periodic scan repairs
missed events. GitLab is the first compiled-in target provider; the internal provider
contract is intentionally small so future providers do not have to imitate GitLab.

## What works today

- discovers every Keycloak group below a configured path prefix;
- maps the hierarchy 1:1 into existing GitLab groups or creates private groups/subgroups;
- adds, raises, and safely prunes direct GitLab memberships;
- resolves users by Keycloak OIDC subject, with explicit username/email compatibility modes;
- protects Owners, the GitLab API identity, custom-role users, and configured break-glass users;
- refuses removal batches above a configured circuit breaker;
- accepts timestamped, replay-protected HMAC event hints and also polls on a fixed interval;
- runs without Kubernetes API credentials in a restricted, single-replica Helm Deployment;
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
prefix, managed GitLab parent, and policy. Secrets are environment-variable references,
never values in the YAML.

```yaml
source:
  type: keycloak
  baseURL: https://keycloak.example.com
  realm: engineering
  clientID: groupbridge
  clientSecretEnv: GROUPBRIDGE_KEYCLOAK_CLIENT_SECRET
  pollInterval: 30s

targets:
  - name: gitlab-main
    type: gitlab
    baseURL: https://gitlab.example.com
    tokenEnv: GROUPBRIDGE_GITLAB_TOKEN
    resolverTokenEnv: GROUPBRIDGE_GITLAB_RESOLVER_TOKEN
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

Group `/gitlab/payments/developers` maps to
`platform/payments/developers`. `targetParent` must already exist; when
`createGroups: true`, GroupBridge may create only the missing descendants. An empty
parent explicitly permits top-level creation on self-managed GitLab and is unsuitable
for GitLab.com.

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

For the safest identity mapping, configure Keycloak OIDC in GitLab with `uid_field: sub`
and set `oidcProvider` to GitLab's provider name (normally `openid_connect`). GroupBridge
queries `extern_uid=<Keycloak user ID>&provider=<name>`. GitLab restricts that lookup to
administrators, so `resolverTokenEnv` is deliberately separate from the parent-scoped
mutation token; constrain and rotate both carefully.

The controller reads `/groups/:id/members`, not effective membership. Every deletion
sets `skip_subresources=true` and `unassign_issuables=false`, so it cannot cascade into
descendant projects or groups.

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
