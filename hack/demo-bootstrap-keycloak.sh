#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

ensure_demo_env
use_demo_context

kc() {
  local command="$1"
  shift
  kubectl -n "${NAMESPACE}" exec keycloak-0 -- \
    /opt/keycloak/bin/kcadm.sh "${command}" "$@" --config /tmp/kcadm.config
}

log "Bootstrapping the Keycloak realm, service clients, listener, and demo identity"
kc config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user "${KEYCLOAK_ADMIN_USERNAME}" \
  --password "${KEYCLOAK_ADMIN_PASSWORD}" >/dev/null

if ! kc get realms/groupbridge >/dev/null 2>&1; then
  kc create realms -s realm=groupbridge -s enabled=true >/dev/null
fi

client_id="$(kc get clients -r groupbridge -q clientId=groupbridge \
  --fields id --format csv --noquotes 2>/dev/null | tr -d '\r' | head -n1)"
if [[ -z "${client_id}" ]]; then
  client_id="$(kc create clients -r groupbridge -i \
    -s clientId=groupbridge \
    -s enabled=true \
    -s publicClient=false \
    -s serviceAccountsEnabled=true \
    -s standardFlowEnabled=false \
    -s "secret=${KEYCLOAK_CLIENT_SECRET}")"
else
  kc update "clients/${client_id}" -r groupbridge \
    -s enabled=true \
    -s publicClient=false \
    -s serviceAccountsEnabled=true \
    -s standardFlowEnabled=false \
    -s "secret=${KEYCLOAK_CLIENT_SECRET}" >/dev/null
fi

kc add-roles -r groupbridge \
  --uusername service-account-groupbridge \
  --cclientid realm-management \
  --rolename query-groups \
  --rolename query-users \
  --rolename view-users >/dev/null 2>&1 || true

gitlab_client_id="$(kc get clients -r groupbridge -q clientId=gitlab \
  --fields id --format csv --noquotes 2>/dev/null | tr -d '\r' | head -n1)"
if [[ -z "${gitlab_client_id}" ]]; then
  gitlab_client_id="$(kc create clients -r groupbridge -i \
    -s clientId=gitlab \
    -s enabled=true \
    -s publicClient=false \
    -s serviceAccountsEnabled=false \
    -s standardFlowEnabled=true \
    -s "secret=${GITLAB_OIDC_CLIENT_SECRET}" \
    -s "redirectUris=[\"http://${DEMO_HOST}:8081/users/auth/openid_connect/callback\"]" \
    -s "webOrigins=[\"http://${DEMO_HOST}:8081\"]")"
else
  kc update "clients/${gitlab_client_id}" -r groupbridge \
    -s enabled=true \
    -s publicClient=false \
    -s standardFlowEnabled=true \
    -s "secret=${GITLAB_OIDC_CLIENT_SECRET}" \
    -s "redirectUris=[\"http://${DEMO_HOST}:8081/users/auth/openid_connect/callback\"]" \
    -s "webOrigins=[\"http://${DEMO_HOST}:8081\"]" >/dev/null
fi

kc update events/config -r groupbridge \
  -s 'eventsListeners=["jboss-logging","groupbridge"]' \
  -s eventsEnabled=true \
  -s adminEventsEnabled=true \
  -s adminEventsDetailsEnabled=false >/dev/null

user_id="$(kc get users -r groupbridge -q "username=${DEMO_USERNAME}" \
  --fields id --format csv --noquotes 2>/dev/null | tr -d '\r' | head -n1)"
if [[ -z "${user_id}" ]]; then
  user_id="$(kc create users -r groupbridge -i \
    -s "username=${DEMO_USERNAME}" \
    -s enabled=true \
    -s emailVerified=true \
    -s "firstName=Alice" \
    -s "lastName=Example" \
    -s "email=${DEMO_USERNAME}@groupbridge.test")"
fi
kc set-password -r groupbridge \
  --userid "${user_id}" \
  --new-password "${DEMO_USER_PASSWORD}" >/dev/null

group_id="$(kc get groups -r groupbridge -q search=developers \
  --fields id,name --format csv --noquotes 2>/dev/null | awk -F, '$2 == "developers" {print $1; exit}' | tr -d '\r')"
if [[ -z "${group_id}" ]]; then
  group_id="$(kc create groups -r groupbridge -i -s name=developers)"
fi
kc update "users/${user_id}/groups/${group_id}" -r groupbridge -n >/dev/null

umask 077
printf '%s\n' "${user_id}" >"${STATE_DIR}/keycloak-alice-id"
log "Keycloak realm groupbridge is ready; ${DEMO_USERNAME} belongs to /developers"
