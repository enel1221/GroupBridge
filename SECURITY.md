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
- GroupBridge never deletes GitLab groups or assigns Owner.
- The pod needs no Kubernetes API token or RBAC.
- TLS verification is on and redirects are refused by both HTTP clients.
- Secrets must be supplied through referenced environment variables/Kubernetes Secrets
  and are not emitted into logs or metrics.

Read [docs/architecture.md](docs/architecture.md) before changing identity resolution,
ownership, prune, event authentication, or GitLab deletion semantics.
