# Contributing

Issues and focused pull requests are welcome. For a behavior change, start with a failing
test and describe the safety effect in the pull request.

```bash
git clone https://github.com/enel1221/GroupBridge.git
cd GroupBridge
make verify
```

The Go controller should stay dependency-light and readable. Use standard-library HTTP,
bounded contexts and bodies, strict config parsing, opaque external IDs, and table-driven
tests. Never log tokens, secrets, webhook bodies, email addresses, or response bodies
that may contain identity data.

Java is limited to the Keycloak listener subtree. It must have no bundled runtime
dependencies beyond JDK modules and Keycloak's provided SPI, and its version must match
the tested Keycloak server exactly.

Provider changes must preserve the invariants in [docs/architecture.md](docs/architecture.md).
In particular, add tests for pagination, partial reads, protected principals, ownership,
removal budgets, target-specific destructive API flags, and retry/idempotency semantics.

Use Conventional Commit-style subjects when practical (`feat:`, `fix:`, `docs:`,
`test:`, `chore:`). By submitting a contribution, you agree that it is licensed under
Apache-2.0.
