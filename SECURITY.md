# Security policy

## Supported versions

Until the first stable release, only the latest tagged release receives security fixes.
Keycloak extension compatibility is pinned to the exact Keycloak line documented in its
README and tested in CI.

## Report a vulnerability

Please use GitHub's **Security → Report a vulnerability** private reporting flow for
`enel1221/GroupBridge`. Do not open a public issue for suspected credential disclosure,
authorization bypass, unsafe pruning, webhook forgery/replay, or supply-chain problems.

Include the affected version, configuration with secrets removed, impact, reproduction,
and any suggested mitigation. You should receive acknowledgement within seven days. No
embargo or disclosure date is promised until scope and a fix are understood.

## Security model

- Keycloak is intentionally authoritative only inside configured source prefixes.
- Events are untrusted hints authenticated with HMAC and replay/freshness checks.
- GitLab mutation is bounded by target paths, allowed roles, protected principals, and
  a removal circuit breaker.
- OIDC username matching requires an exact configured provider and external UID
  identity; it cannot fall back to a colliding local GitLab username. Because the
  external UID is mutable in this mode, deployments must prohibit Keycloak username
  rename/reuse or retire the associated GitLab OIDC identity first.
- GroupBridge never deletes GitLab groups or assigns Owner.
- GroupBridge never reads or mutates Vault secret data, writes Vault ACL policies, or
  deletes Vault identity objects. Vault policies and mounts are GitOps-owned.
- Vault object lifecycle is owned by GitOps/Vault Config Operator. GroupBridge only
  reads exact compiled policies and external groups and performs no identity mutation.
- The pod needs no Kubernetes API token or RBAC.
- Optional Vault auth uses an explicit `audience: vault` projected service-account token
  while automatic Kubernetes API token mounting stays disabled.
- TLS verification is on and redirects are refused by both HTTP clients.
- Secrets must be supplied through referenced environment variables/Kubernetes Secrets
  and are not emitted into logs or metrics.
- Provider credential references are mutually exclusive. File-backed credentials are
  size-bounded, reject control characters, and are reopened for every relevant request;
  errors identify only the source path or environment name, never the value.

Read [docs/architecture.md](docs/architecture.md) before changing identity resolution,
ownership, prune, event authentication, or GitLab deletion semantics.
