#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

require_command kubectl
use_demo_context
exec kubectl -n "${NAMESPACE}" logs deployment/groupbridge --all-pods=true --prefix -f
