#!/usr/bin/env bash
set -euo pipefail

runtime_image=${1:?usage: test-keycloak-listener-runtime.sh KEYCLOAK_RUNTIME_IMAGE}
container_name="groupbridge-keycloak-compat-$$"
database_name="groupbridge-keycloak-database-$$"
network_name="groupbridge-keycloak-network-$$"
admin_password="groupbridge-compatibility-only"
database_password="groupbridge-database-only"
webhook_secret="0123456789abcdef0123456789abcdef"
events_file=$(mktemp)
port_file=$(mktemp)
sink_log=$(mktemp)
sink_pid=

cleanup() {
  if [[ -n "${sink_pid}" ]]; then
    kill "${sink_pid}" >/dev/null 2>&1 || true
    wait "${sink_pid}" >/dev/null 2>&1 || true
  fi
  docker rm --force "${container_name}" >/dev/null 2>&1 || true
  docker rm --force "${database_name}" >/dev/null 2>&1 || true
  docker network rm "${network_name}" >/dev/null 2>&1 || true
  rm -f "${events_file}" "${port_file}" "${sink_log}"
}
trap cleanup EXIT

python3 -u - "${events_file}" "${port_file}" "${webhook_secret}" >"${sink_log}" 2>&1 <<'PY' &
import hashlib
import hmac
import http.server
import json
import pathlib
import re
import sys
import time

events_path = pathlib.Path(sys.argv[1])
port_path = pathlib.Path(sys.argv[2])
webhook_secret = sys.argv[3].encode()
routing_key = re.compile(r"[0-9a-f]{64}")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        timestamp = self.headers.get("X-GroupBridge-Timestamp", "")
        delivery = self.headers.get("X-GroupBridge-Delivery", "")
        signature = self.headers.get("X-GroupBridge-Signature", "")
        expected = "sha256=" + hmac.new(
            webhook_secret,
            timestamp.encode() + b"\n" + delivery.encode() + b"\n" + body,
            hashlib.sha256,
        ).hexdigest()
        try:
            event = json.loads(body)
            timestamp_value = int(timestamp)
            if abs(time.time() - timestamp_value) > 300:
                raise ValueError("stale webhook timestamp")
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid HMAC signature")
            if not delivery or event.get("eventId") != delivery:
                raise ValueError("delivery does not match eventId")
            if any(field in event for field in ("resourcePath", "resourceId", "realmId")):
                raise ValueError("payload contains a forbidden raw identifier field")
            resource_type = event.get("resourceType")
            operation_type = event.get("operationType")
            group_key = event.get("groupKey")
            user_key = event.get("userKey")
            if resource_type == "USER" and operation_type == "LOGIN":
                if group_key is not None or not routing_key.fullmatch(user_key or ""):
                    raise ValueError("login payload lacks its typed user routing key")
            elif (
                resource_type == "USER"
                and operation_type in ("UPDATE", "DELETE")
                and user_key is not None
            ):
                if group_key is not None or not routing_key.fullmatch(user_key or ""):
                    raise ValueError("direct user payload lacks its typed user routing key")
            elif resource_type == "GROUP" or resource_type in ("GROUP_MEMBERSHIP", "USER"):
                if user_key is not None or not routing_key.fullmatch(group_key or ""):
                    raise ValueError("admin payload lacks its typed group routing key")
            else:
                raise ValueError("unexpected event classification")
        except (ValueError, json.JSONDecodeError) as error:
            print(f"rejected webhook capture: {error}", flush=True)
            self.send_response(401)
            self.end_headers()
            return
        with events_path.open("ab") as events:
            events.write(body + b"\n")
            events.flush()
        self.send_response(202)
        self.end_headers()

    def log_message(self, *_args):
        return


server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
port_path.write_text(str(server.server_port), encoding="utf-8")
server.serve_forever()
PY
sink_pid=$!

sink_port=
for _ in $(seq 1 50); do
  if [[ -s "${port_file}" ]]; then
    sink_port=$(<"${port_file}")
    break
  fi
  sleep 0.1
done
if [[ -z "${sink_port}" ]]; then
  cat "${sink_log}" >&2
  echo "Webhook capture server did not become ready" >&2
  exit 1
fi

persisted_config=$(docker run --rm "${runtime_image}" show-config 2>&1)
if ! grep -Eq 'kc\.features = +scripts \(Persisted(ConfigSource)?\)' <<<"${persisted_config}"; then
  echo "${persisted_config}" >&2
  echo "Optimized Keycloak runtime did not persist the scripts feature" >&2
  exit 1
fi

docker network create "${network_name}" >/dev/null
docker run --detach --name "${database_name}" \
  --network "${network_name}" \
  --network-alias postgres \
  -e POSTGRES_DB=keycloak \
  -e POSTGRES_USER=keycloak \
  -e POSTGRES_PASSWORD="${database_password}" \
  postgres:17.6-alpine3.22@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94 \
  >/dev/null

docker run --detach --name "${container_name}" \
  --network "${network_name}" \
  --add-host host.docker.internal:host-gateway \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="${admin_password}" \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD="${admin_password}" \
  -e KC_DB=postgres \
  -e KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak \
  -e KC_DB_USERNAME=keycloak \
  -e KC_DB_PASSWORD="${database_password}" \
  -e KC_FEATURES=scripts \
  -e KC_HTTP_ENABLED=true \
  -e KC_HOSTNAME_STRICT=false \
  -e KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__WEBHOOK_URL="http://host.docker.internal:${sink_port}/v1/events/keycloak" \
  -e KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__WEBHOOK_SECRET="${webhook_secret}" \
  -e KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__ALLOW_INSECURE_HTTP=true \
  -e KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__JIT_CLIENT_IDS=admin-cli \
  -e KC_SPI_EVENTS_LISTENER_GROUPBRIDGE_WEBHOOK_URL="http://host.docker.internal:${sink_port}/v1/events/keycloak" \
  -e KC_SPI_EVENTS_LISTENER_GROUPBRIDGE_WEBHOOK_SECRET="${webhook_secret}" \
  -e KC_SPI_EVENTS_LISTENER_GROUPBRIDGE_ALLOW_INSECURE_HTTP=true \
  -e KC_SPI_EVENTS_LISTENER_GROUPBRIDGE_JIT_CLIENT_IDS=admin-cli \
  "${runtime_image}" start --optimized >/dev/null

ready=false
for _ in $(seq 1 120); do
  if docker exec "${container_name}" \
    /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://127.0.0.1:8080 \
    --realm master \
    --user admin \
    --password "${admin_password}" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "${ready}" != true ]]; then
  docker logs "${container_name}" >&2
  echo "Keycloak did not become ready" >&2
  exit 1
fi

runtime_logs=$(docker logs "${container_name}" 2>&1)
if grep -Eqi 'build[- ]time.*(different|mismatch|not used)|optimized.*(disabled|ignored)' <<<"${runtime_logs}"; then
  echo "${runtime_logs}" >&2
  echo "Optimized Keycloak runtime reported a build-time configuration mismatch" >&2
  exit 1
fi

docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh update events/config \
  -r master \
  -s 'eventsEnabled=true' \
  -s 'adminEventsEnabled=true' \
  -s 'adminEventsDetailsEnabled=false' \
  -s 'eventsListeners=["groupbridge"]'
login_start=$(wc -l <"${events_file}" | tr -d ' ')
docker exec "${container_name}" \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://127.0.0.1:8080 \
  --realm master \
  --user admin \
  --password "${admin_password}" >/dev/null

wait_for_event() {
  local description=$1
  local resource_type_regex=$2
  local operation_type=$3
  local start_line=$4
  local matched=false

  for _ in $(seq 1 50); do
    if python3 - "${events_file}" "${resource_type_regex}" "${operation_type}" "${start_line}" <<'PY'
import json
import pathlib
import re
import sys

events_path = pathlib.Path(sys.argv[1])
resource_type = re.compile(sys.argv[2])
operation_type = sys.argv[3]
start_line = int(sys.argv[4])
for line in events_path.read_text(encoding="utf-8").splitlines()[start_line:]:
    event = json.loads(line)
    if resource_type.fullmatch(event.get("resourceType", "")) and event.get("operationType") == operation_type:
        raise SystemExit(0)
raise SystemExit(1)
PY
    then
      matched=true
      break
    fi
    sleep 0.2
  done

  if [[ "${matched}" != true ]]; then
    cat "${events_file}" >&2
    cat "${sink_log}" >&2
    echo "Keycloak did not emit ${description}" >&2
    exit 1
  fi
}

wait_for_event "an allowlisted login hint" "USER" "LOGIN" "${login_start}"

group_start=$(wc -l <"${events_file}" | tr -d ' ')
group_id=$(docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh create groups \
  -r master \
  -s name=groupbridge-listener-compatibility \
  -i)
wait_for_event "a GROUP CREATE hint" "GROUP" "CREATE" "${group_start}"

user_id=$(docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh create users \
  -r master \
  -s username=groupbridge-listener-compatibility \
  -s enabled=true \
  -i)
membership_add_start=$(wc -l <"${events_file}" | tr -d ' ')
docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh update \
  "users/${user_id}/groups/${group_id}" \
  -r master \
  -n
wait_for_event "a membership ADD hint" "GROUP_MEMBERSHIP|USER" "CREATE" "${membership_add_start}"

membership_delete_start=$(wc -l <"${events_file}" | tr -d ' ')
docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh delete \
  "users/${user_id}/groups/${group_id}" \
  -r master
wait_for_event "a membership DELETE hint" "GROUP_MEMBERSHIP|USER" "DELETE" "${membership_delete_start}"

user_update_start=$(wc -l <"${events_file}" | tr -d ' ')
docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh update \
  "users/${user_id}" \
  -r master \
  -s enabled=false
wait_for_event "a direct USER UPDATE hint" "USER" "UPDATE" "${user_update_start}"

user_delete_start=$(wc -l <"${events_file}" | tr -d ' ')
docker exec "${container_name}" /opt/keycloak/bin/kcadm.sh delete \
  "users/${user_id}" \
  -r master
wait_for_event "a direct USER DELETE hint" "USER" "DELETE" "${user_delete_start}"

events_json=$(<"${events_file}")
if grep -Eq '"resource(Path|Id)"[[:space:]]*:' <<<"${events_json}"; then
  echo "${events_json}" >&2
  echo "Keycloak listener leaked an admin resource path or identifier" >&2
  exit 1
fi
if grep -Fq "${group_id}" <<<"${events_json}" || grep -Fq "${user_id}" <<<"${events_json}"; then
  echo "${events_json}" >&2
  echo "Keycloak listener leaked a raw group or user identifier" >&2
  exit 1
fi

runtime_logs=$(docker logs "${container_name}" 2>&1)
if grep -Eq 'NoSuchMethodError|NoClassDefFoundError|ClassNotFoundException|LinkageError' <<<"${runtime_logs}"; then
  echo "${runtime_logs}" >&2
  echo "Keycloak listener has a runtime linkage failure" >&2
  exit 1
fi

echo "Keycloak optimized runtime persisted scripts and emitted signed typed login, group, membership, and direct-user phases"
