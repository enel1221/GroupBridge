#!/usr/bin/env bash

set -Eeuo pipefail
# shellcheck source=hack/lib/demo-common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/demo-common.sh"

ensure_demo_env
use_demo_context
for command in curl jq; do require_command "${command}"; done
[[ -s "${STATE_DIR}/keycloak-alice-id" ]] || die "Keycloak demo user ID is missing; run demo-bootstrap-keycloak.sh first"
KEYCLOAK_ALICE_ID="$(<"${STATE_DIR}/keycloak-alice-id")"

log "Bootstrapping the GitLab API token"
kubectl -n "${NAMESPACE}" exec gitlab-0 -- env \
  GROUPBRIDGE_TOKEN="${GITLAB_TOKEN}" \
  gitlab-rails runner '
    root = User.find_by_username!("root")
    token = root.personal_access_tokens.find_or_initialize_by(name: "groupbridge-demo")
    token.scopes = ["api"]
    token.expires_at = Date.current + 365
    token.set_token(ENV.fetch("GROUPBRIDGE_TOKEN"))
    token.save!
  '

api="http://${DEMO_HOST}:8081/api/v4"
user_id="$(curl --fail --silent --show-error --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  --get --data-urlencode "username=${DEMO_USERNAME}" "${api}/users" | jq -r '.[0].id // empty')"
if [[ -z "${user_id}" ]]; then
  user_id="$(curl --fail --silent --show-error --request POST \
    --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
    --data-urlencode "username=${DEMO_USERNAME}" \
    --data-urlencode "name=Alice Example" \
    --data-urlencode "email=${DEMO_USERNAME}@groupbridge.test" \
    --data-urlencode "password=${DEMO_USER_PASSWORD}" \
    --data-urlencode "skip_confirmation=true" \
    "${api}/users" | jq -r .id)"
fi
[[ -n "${user_id}" && "${user_id}" != null ]] || die "GitLab demo user creation failed"

log "Linking the GitLab demo user to its Keycloak OIDC subject"
kubectl -n "${NAMESPACE}" exec gitlab-0 -- env \
  GROUPBRIDGE_USERNAME="${DEMO_USERNAME}" \
  GROUPBRIDGE_KEYCLOAK_ID="${KEYCLOAK_ALICE_ID}" \
  gitlab-rails runner '
    user = User.find_by_username!(ENV.fetch("GROUPBRIDGE_USERNAME"))
    identity = Identity.find_or_initialize_by(user: user, provider: "openid_connect")
    identity.extern_uid = ENV.fetch("GROUPBRIDGE_KEYCLOAK_ID")
    identity.save!
  '
log "GitLab API access and demo identity are ready"
