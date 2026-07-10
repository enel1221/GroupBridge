---
name: release
description: Prepare and verify a secure GroupBridge semantic release and GHCR artifacts.
---

# Release GroupBridge

1. Read `/AGENTS.md`, `/SECURITY.md`, `/CHANGELOG.md`, both Dockerfiles, the Helm chart,
   and all GitHub workflows.
2. Confirm the Keycloak dependency and runtime image are the same tested patch version.
   Review current upstream security releases before changing a pin.
3. Run `make verify`, the Java provider tests, container builds, Helm render/schema tests,
   and the full k3d behavior test.
4. Confirm images run non-root, the controller image is shell-less, the JAR has no bundled
   dependencies, and no generated credentials or kubeconfig are tracked.
5. Move changelog entries into the semantic version, update chart `version`/`appVersion`,
   and tag `vX.Y.Z` from a clean signed-off commit.
6. Observe CI publishing controller and Keycloak images plus the OCI chart to GHCR.
   Verify immutable digests, SBOM/provenance/attestations, chart install, and release notes.
7. Do not overwrite an existing tag or artifact. Stop and report any ambiguous or failed
   verification.
