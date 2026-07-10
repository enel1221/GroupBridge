#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="${GROUPBRIDGE_STATE_DIR:-${ROOT_DIR}/.groupbridge}"
ENV_FILE="${STATE_DIR}/demo.env"
REMOTE_KUBECONFIG="${STATE_DIR}/kubeconfig-remote.yaml"
CLUSTER_NAME="${GROUPBRIDGE_CLUSTER_NAME:-groupbridge}"
NAMESPACE="${GROUPBRIDGE_DEMO_NAMESPACE:-groupbridge-demo}"

log() {
  printf '\n[groupbridge] %s\n' "$*"
}

die() {
  printf '\n[groupbridge] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

detect_host_ip() {
  local detected
  if [[ -n "${GROUPBRIDGE_DEMO_HOST:-}" ]]; then
    detected="${GROUPBRIDGE_DEMO_HOST}"
  else
    detected="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')"
  fi
  [[ "${detected}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || \
    die "could not detect a LAN IPv4 address; set GROUPBRIDGE_DEMO_HOST"
  printf '%s' "${detected}"
}

ensure_demo_env() {
  require_command openssl
  mkdir -p "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"

  if [[ ! -f "${ENV_FILE}" ]]; then
    local host
    host="$(detect_host_ip)"
    umask 077
    {
      printf 'DEMO_HOST=%q\n' "${host}"
      printf 'POSTGRES_PASSWORD=%q\n' "$(openssl rand -hex 24)"
      printf 'KEYCLOAK_ADMIN_USERNAME=%q\n' "admin"
      printf 'KEYCLOAK_ADMIN_PASSWORD=%q\n' "$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)"
      printf 'KEYCLOAK_CLIENT_SECRET=%q\n' "$(openssl rand -hex 32)"
      printf 'GITLAB_OIDC_CLIENT_SECRET=%q\n' "$(openssl rand -hex 32)"
      printf 'GITLAB_ROOT_PASSWORD=%q\n' "$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)"
      printf 'GITLAB_TOKEN=%q\n' "glpat-$(openssl rand -hex 20)"
      printf 'WEBHOOK_SECRET=%q\n' "$(openssl rand -hex 32)"
      printf 'DEMO_USERNAME=%q\n' "alice"
      printf 'DEMO_USER_PASSWORD=%q\n' "$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)"
    } >"${ENV_FILE}"
  fi

  chmod 600 "${ENV_FILE}"
  # The file is generated locally by this script and contains shell-escaped
  # scalar values only.
  # shellcheck disable=SC1090
  source "${ENV_FILE}"

  if [[ -n "${GROUPBRIDGE_DEMO_HOST:-}" && "${DEMO_HOST}" != "${GROUPBRIDGE_DEMO_HOST}" ]]; then
    die "demo secrets were generated for ${DEMO_HOST}; remove ${ENV_FILE} or unset GROUPBRIDGE_DEMO_HOST"
  fi
}

cluster_exists() {
  k3d cluster list --no-headers 2>/dev/null | awk '{print $1}' | grep -Fxq "${CLUSTER_NAME}"
}

use_demo_context() {
  kubectl config use-context "k3d-${CLUSTER_NAME}" >/dev/null
}

write_remote_kubeconfig() {
  local temporary
  temporary="$(mktemp "${STATE_DIR}/kubeconfig.XXXXXX")"
  k3d kubeconfig get "${CLUSTER_NAME}" >"${temporary}"
  sed -E "s#server: https://(0\.0\.0\.0|127\.0\.0\.1|localhost):6550#server: https://${DEMO_HOST}:6550#" \
    "${temporary}" >"${REMOTE_KUBECONFIG}"
  rm -f "${temporary}"
  chmod 600 "${REMOTE_KUBECONFIG}"
}

print_access() {
  cat <<EOF

GroupBridge local demo is ready.

  Keycloak admin: http://${DEMO_HOST}:8080/admin/
    username: ${KEYCLOAK_ADMIN_USERNAME}
    password: ${KEYCLOAK_ADMIN_PASSWORD}

  GitLab:         http://${DEMO_HOST}:8081
    root username: root
    root password: ${GITLAB_ROOT_PASSWORD}
    demo username: ${DEMO_USERNAME}
    demo password: ${DEMO_USER_PASSWORD}
    OIDC login: click "Keycloak" on the GitLab sign-in page

  Kubernetes API: https://${DEMO_HOST}:6550
  Remote kubeconfig: ${REMOTE_KUBECONFIG}

From another machine, copy the kubeconfig and use it directly:
  scp $(id -un)@${DEMO_HOST}:${REMOTE_KUBECONFIG} ./groupbridge-kubeconfig
  KUBECONFIG=./groupbridge-kubeconfig kubectl get pods -n ${NAMESPACE}

Headlamp can import ./groupbridge-kubeconfig. Port 6550 grants Kubernetes admin
access; restrict it to your trusted LAN with the host firewall.

Useful local commands:
  kubectl -n ${NAMESPACE} get pods
  kubectl -n ${NAMESPACE} logs deployment/groupbridge -f
EOF
}
