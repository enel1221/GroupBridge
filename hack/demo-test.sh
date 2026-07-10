#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

for command in curl jq kubectl; do require_command "${command}"; done
ensure_demo_env
use_demo_context

kc() {
  local command="$1"
  shift
  kubectl -n "${NAMESPACE}" exec keycloak-0 -- \
    /opt/keycloak/bin/kcadm.sh "${command}" "$@" --config /tmp/kcadm.config
}

wait_for() {
  local description="$1"
  local check="$2"
  local deadline=$((SECONDS + 180))
  until "${check}"; do
    (( SECONDS < deadline )) || die "timed out waiting for ${description}"
    sleep 2
  done
}

api="http://${DEMO_HOST}:8081/api/v4"
gitlab_get() { curl --fail --silent --show-error --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" "$@"; }
group_exists() {
  group_json="$(gitlab_get "${api}/groups/developers" 2>/dev/null)" || return 1
  [[ "$(jq -r .id <<<"${group_json}")" != null ]]
}

log "Waiting for GroupBridge and the /developers GitLab group"
kubectl -n "${NAMESPACE}" rollout status deployment/groupbridge --timeout=5m
group_json=""
wait_for "GitLab developers group" group_exists
group_id="$(jq -r .id <<<"${group_json}")"

user_id="$(kc get users -r groupbridge -q "username=${DEMO_USERNAME}" --fields id --format csv --noquotes | tr -d '\r' | head -n1)"
group_source_id="$(kc get groups -r groupbridge -q search=developers --fields id,name --format csv --noquotes | awk -F, '$2 == "developers" {print $1; exit}' | tr -d '\r')"
[[ -n "${user_id}" && -n "${group_source_id}" ]] || die "demo user or source group is missing"

has_direct_member() {
  gitlab_get "${api}/groups/${group_id}/members?per_page=100" | \
    jq -e --arg username "${DEMO_USERNAME}" 'any(.[]; .username == $username)' >/dev/null
}
lacks_direct_member() { ! has_direct_member; }

wait_for "initial GitLab membership" has_direct_member
log "Removing ${DEMO_USERNAME} from Keycloak; two complete snapshots are required before prune"
kc delete "users/${user_id}/groups/${group_source_id}" -r groupbridge >/dev/null
wait_for "GitLab membership removal" lacks_direct_member

log "Restoring the Keycloak membership"
kc update "users/${user_id}/groups/${group_source_id}" -r groupbridge -n >/dev/null
wait_for "GitLab membership restoration" has_direct_member

log "End-to-end membership removal and restoration passed"
