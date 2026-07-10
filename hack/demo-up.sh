#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

SKIP_BUILD=false
if [[ "${1:-}" == "--skip-build" ]]; then
  SKIP_BUILD=true
elif [[ $# -gt 0 ]]; then
  die "usage: $0 [--skip-build]"
fi

for command in docker k3d kubectl helm openssl ip sed; do
  require_command "${command}"
done
docker info >/dev/null 2>&1 || die "Docker is not reachable by the current user"
ensure_demo_env

REUSED_CLUSTER=false
if ! cluster_exists; then
  log "Creating k3d cluster ${CLUSTER_NAME} with API bound to 0.0.0.0:6550"
  rendered_config="${STATE_DIR}/k3d.yaml"
  sed "s/__HOST_IP__/${DEMO_HOST}/g" "${ROOT_DIR}/deploy/k3d/groupbridge.yaml" >"${rendered_config}"
  k3d cluster create --config "${rendered_config}"
else
  REUSED_CLUSTER=true
  log "Reusing k3d cluster ${CLUSTER_NAME}"
fi
use_demo_context

if [[ "${SKIP_BUILD}" == false ]]; then
  log "Building the controller and customized Keycloak images with Docker"
  docker build -t groupbridge:dev "${ROOT_DIR}"
  docker build -t groupbridge-keycloak-extension:dev \
    "${ROOT_DIR}/extensions/keycloak-event-listener"
  docker build \
    --build-arg PROVIDER_IMAGE=groupbridge-keycloak-extension:dev \
    -t groupbridge-keycloak:dev \
    -f "${ROOT_DIR}/deploy/keycloak/Dockerfile" \
    "${ROOT_DIR}"
fi

for image in groupbridge:dev groupbridge-keycloak:dev; do
  docker image inspect "${image}" >/dev/null 2>&1 || \
    die "local image ${image} is missing; rerun without --skip-build"
done

log "Importing local images into k3d"
k3d image import -c "${CLUSTER_NAME}" groupbridge:dev groupbridge-keycloak:dev

kubectl apply -f "${ROOT_DIR}/deploy/demo/namespace.yaml"
kubectl -n "${NAMESPACE}" create secret generic demo-credentials \
  --from-literal=demo-host="${DEMO_HOST}" \
  --from-literal=postgres-password="${POSTGRES_PASSWORD}" \
  --from-literal=keycloak-admin-username="${KEYCLOAK_ADMIN_USERNAME}" \
  --from-literal=keycloak-admin-password="${KEYCLOAK_ADMIN_PASSWORD}" \
  --from-literal=keycloak-client-secret="${KEYCLOAK_CLIENT_SECRET}" \
  --from-literal=gitlab-oidc-client-secret="${GITLAB_OIDC_CLIENT_SECRET}" \
  --from-literal=gitlab-root-password="${GITLAB_ROOT_PASSWORD}" \
  --from-literal=gitlab-token="${GITLAB_TOKEN}" \
  --from-literal=gitlab-resolver-token="${GITLAB_TOKEN}" \
  --from-literal=webhook-secret="${WEBHOOK_SECRET}" \
  --from-literal=demo-user-password="${DEMO_USER_PASSWORD}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "${NAMESPACE}" create secret generic groupbridge \
  --from-literal=keycloak-client-secret="${KEYCLOAK_CLIENT_SECRET}" \
  --from-literal=gitlab-token="${GITLAB_TOKEN}" \
  --from-literal=gitlab-resolver-token="${GITLAB_TOKEN}" \
  --from-literal=webhook-secret="${WEBHOOK_SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f -

log "Starting pinned Postgres, Keycloak, and GitLab services"
kubectl apply -f "${ROOT_DIR}/deploy/demo/postgres.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/demo/keycloak.yaml"
kubectl apply -f "${ROOT_DIR}/deploy/demo/gitlab.yaml"

if [[ "${REUSED_CLUSTER}" == true && "${SKIP_BUILD}" == false ]]; then
  log "Restarting Keycloak to load the newly imported provider image"
  kubectl -n "${NAMESPACE}" rollout restart statefulset/keycloak
fi

kubectl -n "${NAMESPACE}" rollout status statefulset/postgres --timeout=5m
kubectl -n "${NAMESPACE}" rollout status statefulset/keycloak --timeout=10m
"${ROOT_DIR}/hack/demo-bootstrap-keycloak.sh"

log "Waiting for GitLab; first boot commonly takes 5-15 minutes"
kubectl -n "${NAMESPACE}" rollout status statefulset/gitlab --timeout=30m
"${ROOT_DIR}/hack/demo-bootstrap-gitlab.sh"

log "Installing GroupBridge with the local Helm chart"
helm upgrade --install groupbridge "${ROOT_DIR}/charts/groupbridge" \
  --namespace "${NAMESPACE}" \
  --values "${ROOT_DIR}/deploy/demo/groupbridge-values.yaml" \
  --wait \
  --timeout 5m

if [[ "${REUSED_CLUSTER}" == true && "${SKIP_BUILD}" == false ]]; then
  log "Restarting GroupBridge to load the newly imported controller image"
  kubectl -n "${NAMESPACE}" rollout restart deployment/groupbridge
  kubectl -n "${NAMESPACE}" rollout status deployment/groupbridge --timeout=5m
fi

write_remote_kubeconfig
print_access
