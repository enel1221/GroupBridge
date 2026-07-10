# GroupBridge Keycloak event listener

This is the only Java component in GroupBridge. It is a small Keycloak
`EventListenerProvider` that turns successful group and membership admin events, logins,
and registrations into authenticated reconciliation hints. GroupBridge always reads
current state back from Keycloak; the webhook is intentionally not a durable event log.

The provider is pinned to Keycloak **26.6.4** and Java 21. Its JAR contains no runtime
libraries: it uses Keycloak's supplied SPI and the JDK HTTP and cryptography APIs.
Keycloak currently labels the documented event-listener SPI as internal, so its
`KC-SERVICES0047` startup warning is expected. Matching the provider and server versions
is required; upgrade and test them together.

Accordingly, the build has a `provided` dependency on
`keycloak-server-spi-private`. Keycloak 26.6.4 places `EventListenerProvider`,
`EventListenerProviderFactory`, `Event`, `EventType`, `AdminEvent`, `OperationType`, and
`ResourceType` there rather than in `keycloak-server-spi`; a compile check without the
private artifact fails on those symbols. It is never bundled in the GroupBridge JAR.

## What it sends

The listener accepts these successful events:

- `GROUP`, including create, update, and delete;
- `GROUP_MEMBERSHIP`; and
- a path shaped like `users/{user-id}/groups/{group-id}` when Keycloak reports its
  resource type as `USER`; and
- successful `LOGIN` and `REGISTER` user events, to accelerate reconciliation before a
  user's first GitLab login.

It ignores unrelated and failed events. An immutable, metadata-only hint is queued only
after Keycloak's transaction commits. Network delivery runs on a small daemon worker
pool, never on the Keycloak request thread. There are no retries: a periodic GroupBridge
full reconciliation is the recovery mechanism.

The canonical JSON body is deliberately metadata-only:

```json
{
  "specVersion": "1.0",
  "eventId": "2250cc6b-11bb-4e47-8370-1799ad7c33ec",
  "occurredAt": "2026-07-10T12:34:56.789Z",
  "realmId": "e10ed343-58d0-424d-a129-13bc4b020689",
  "realmName": "engineering",
  "resourceType": "GROUP_MEMBERSHIP",
  "operationType": "CREATE",
  "resourcePath": "users/user-id/groups/group-id",
  "resourceId": "group-id"
}
```

Representations, usernames, email addresses, tokens, admin authentication details, and
the webhook secret are never added to the payload or logs.

Login and registration hints use the same envelope with `resourceType: "USER"` and
`operationType: "LOGIN"` or `"REGISTER"`. Their `resourcePath` and `resourceId` are
`null`; client ID, user ID, username, session ID, IP address, and event details are all
omitted. These events are wake-ups, not identity data.

## Build and test

With Maven 3.9 and JDK 21:

```bash
mvn -B -ntp verify
```

Without a local Java toolchain, build the OCI artifact:

```bash
docker build -t groupbridge-keycloak-extension:dev .
```

The build runs all tests. The resulting scratch image contains exactly one file:
`/provider/groupbridge-keycloak-event-listener.jar`.

## Install in Keycloak

Keycloak custom providers run in the server's shared class loader, so install only a JAR
you built or obtained from a trusted GroupBridge release. Copy the JAR to
`/opt/keycloak/providers/`, then run `kc.sh build`. An optimized runtime image can use
the extension artifact as a named build context:

```dockerfile
FROM groupbridge-keycloak-extension:dev AS groupbridge_provider
FROM quay.io/keycloak/keycloak:26.6.4 AS builder
COPY --from=groupbridge_provider \
  /provider/groupbridge-keycloak-event-listener.jar \
  /opt/keycloak/providers/groupbridge-keycloak-event-listener.jar
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.6.4
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
```

For a direct installation instead:

```bash
cp target/groupbridge-keycloak-event-listener-0.1.0-SNAPSHOT.jar \
  /opt/keycloak/providers/groupbridge-keycloak-event-listener.jar
/opt/keycloak/bin/kc.sh build
```

## Configure

The provider ID is `groupbridge`. Set its runtime options through Keycloak configuration:

| Environment variable | CLI option | Required/default |
| --- | --- | --- |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__WEBHOOK_URL` | `--spi-events-listener--groupbridge--webhook-url` | required; HTTPS |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__WEBHOOK_SECRET` | `--spi-events-listener--groupbridge--webhook-secret` | required; at least 32 UTF-8 bytes |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__ALLOW_INSECURE_HTTP` | `--spi-events-listener--groupbridge--allow-insecure-http` | `false` |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__CONNECT_TIMEOUT_MS` | `--spi-events-listener--groupbridge--connect-timeout-ms` | `2000`; maximum `10000` |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__REQUEST_TIMEOUT_MS` | `--spi-events-listener--groupbridge--request-timeout-ms` | `3000`; maximum `30000` |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__WORKER_THREADS` | `--spi-events-listener--groupbridge--worker-threads` | `2`; maximum `4` |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__QUEUE_CAPACITY` | `--spi-events-listener--groupbridge--queue-capacity` | `256`; maximum `4096` |
| `KC_SPI_EVENTS_LISTENER__GROUPBRIDGE__SHUTDOWN_TIMEOUT_MS` | `--spi-events-listener--groupbridge--shutdown-timeout-ms` | `2000`; maximum `10000` |

For an in-cluster development deployment, the webhook URL is normally
`http://groupbridge:8080/v1/events/keycloak` together with the explicit
`allow-insecure-http=true` setting. Use the TLS service URL in production.

Generate a shared secret and store the same value in the Keycloak and GroupBridge
Kubernetes Secrets:

```bash
openssl rand -hex 32
```

Use HTTPS in production. Plain HTTP requires the explicit
`allow-insecure-http=true` escape hatch and is intended only for a trusted local demo
network. Redirects are never followed, URL credentials and fragments are rejected, and
both connection and whole-request timeouts are bounded.

Finally, enable `groupbridge` in each realm that GroupBridge manages. Preserve any
existing listeners:

```bash
/opt/keycloak/bin/kcadm.sh update events/config -r engineering \
  -s 'eventsEnabled=true' \
  -s 'adminEventsEnabled=true' \
  -s 'adminEventsDetailsEnabled=false' \
  -s 'eventsListeners=["jboss-logging","groupbridge"]'
```

`adminEventsDetailsEnabled=false` avoids retaining or exposing resource
representations; GroupBridge does not need them.

## Verify signatures

Every request has:

- `X-GroupBridge-Timestamp`: Unix seconds;
- `X-GroupBridge-Delivery`: event ID, or a generated UUID if Keycloak omitted one; and
- `X-GroupBridge-Signature`: `sha256=<lowercase hex HMAC-SHA256>`.

The signed bytes are exactly:

```text
<timestamp>\n<delivery-id>\n<raw-request-body>
```

The receiver must reject stale timestamps, duplicate delivery IDs, malformed signature
headers, and signatures that fail a constant-time comparison. It should return a 2xx
response only after the reconciliation hint has been accepted.

## Operational behavior

- A non-2xx response or network failure is logged with only the delivery ID, HTTP status,
  and exception class. URLs, bodies, and secrets are not logged.
- The after-completion callback only submits an immutable hint to a bounded in-memory
  queue. Two daemon workers perform HTTP requests by default, each bounded by the request
  timeout.
- When the queue is saturated or shutting down, the new hint is dropped immediately and
  only its delivery ID is logged. The Keycloak admin or login request is never delayed by
  network I/O.
- Shutdown waits only for the configured bounded grace period, then interrupts active
  delivery, drops queued hints, closes the HTTP client, and returns. Worker threads are
  daemon threads as an additional process-exit safeguard.
- The provider does not follow redirects and does not retry. GroupBridge's full scan must
  remain enabled so a temporary outage cannot cause permanent drift.
- To uninstall, remove the JAR from `/opt/keycloak/providers/` and run `kc.sh build` again.

See the official Keycloak documentation for [implementing an Event Listener SPI](https://www.keycloak.org/docs/latest/server_development/index.html#_events)
and [installing providers](https://www.keycloak.org/server/configuration-provider).
