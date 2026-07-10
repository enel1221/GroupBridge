---
name: add-provider
description: Add or extend a GroupBridge target provider without weakening reconciliation safety.
---

# Add a GroupBridge provider

1. Read `/AGENTS.md`, `/docs/architecture.md`, `/SECURITY.md`, and the existing provider
   interface and GitLab implementation completely.
2. Write a native target model. Do not force policy, alias, team, or repository concepts
   into group membership; introduce a small capability interface when needed.
3. Write contract tests first for pagination, idempotency, partial reads, ownership,
   protected principals, destructive API flags, rate limiting, and sanitized errors.
4. Use stable external IDs as canonical keys. Paths/names are locators only.
5. Put all network calls behind bounded contexts, response limits, TLS verification, and
   a no-cross-origin-redirect policy. Never log response bodies or authentication data.
6. Register the provider explicitly in `cmd/groupbridge/main.go`; do not load dynamic
   plugins.
7. Extend strict config validation, examples, Helm values/schema, architecture docs, and
   operational troubleshooting.
8. Run `make verify` and the provider integration test before reporting completion.
