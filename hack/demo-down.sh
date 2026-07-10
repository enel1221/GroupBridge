#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
  PURGE=true
elif [[ $# -gt 0 ]]; then
  die "usage: $0 [--purge]"
fi

require_command k3d
if cluster_exists; then
  log "Deleting k3d cluster ${CLUSTER_NAME} and its demo volumes"
  k3d cluster delete "${CLUSTER_NAME}"
else
  log "k3d cluster ${CLUSTER_NAME} is already absent"
fi

if [[ "${PURGE}" == true ]]; then
  log "Removing persisted local demo credentials"
  rm -rf "${STATE_DIR}"
else
  log "Credentials remain in ${ENV_FILE}; use --purge to remove them"
fi
