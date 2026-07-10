#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

for command in k3d kubectl; do
  require_command "${command}"
done
ensure_demo_env
cluster_exists || die "k3d cluster ${CLUSTER_NAME} does not exist; run hack/demo-up.sh"
use_demo_context
write_remote_kubeconfig

kubectl -n "${NAMESPACE}" get pods,services,persistentvolumeclaims
print_access
