---
name: local-demo
description: Build, diagnose, or validate the complete GroupBridge k3d demonstration safely.
---

# Work with the local demo

1. Read `/AGENTS.md`, `/README.md`, `/deploy/k3d/groupbridge.yaml`, and every
   `/hack/demo-*.sh` file before acting.
2. Run `make demo-status` before creating or deleting anything. Reuse the existing demo
   when healthy.
3. Generated secrets and kubeconfig belong only in `/.groupbridge/` with restrictive
   permissions. Never display secret values except where the explicit demo status output
   is designed to hand credentials to the local operator.
4. Use `make demo-up HOST_IP=<LAN IP>` for creation. Validate Keycloak, GitLab,
   GroupBridge health, remote kubeconfig SAN/connectivity, OIDC login, group creation,
   membership add, membership removal, and repair after a dropped webhook.
5. Use `make demo-down` for cleanup. Do not delete unrelated k3d clusters, Docker images,
   volumes, or kubeconfig contexts.
6. When diagnosing a failure, collect pod state, Kubernetes events, and scoped logs with
   secrets redacted. GitLab first boot may legitimately take 15 minutes.
