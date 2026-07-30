package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;

class WebhookPayloadTest {
    private static final byte[] SECRET =
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    void emitsStableMinimalJsonWithoutRepresentationOrAuthDetails() {
        AdminEvent event = new AdminEvent();
        event.setTime(1_700_000_000_123L);
        event.setRealmId("realm-1");
        event.setRealmName("engineering\n\"east\"");
        event.setResourceType(ResourceType.GROUP_MEMBERSHIP);
        event.setOperationType(OperationType.CREATE);
        event.setResourcePath("users/user-1/groups/group-1");
        event.setRepresentation("{\"email\":\"private@example.test\"}");

        final String json;
        try (RoutingKey routingKey = new RoutingKey(SECRET)) {
            json = new String(
                    WebhookPayload.from(event, "event-1", routingKey).toJson(),
                    StandardCharsets.UTF_8);
        }

        assertEquals(
                "{\"specVersion\":\"1.0\",\"eventId\":\"event-1\","
                        + "\"occurredAt\":\"2023-11-14T22:13:20.123Z\","
                        + "\"realmName\":\"engineering\\n\\\"east\\\"\","
                        + "\"resourceType\":\"GROUP_MEMBERSHIP\",\"operationType\":\"CREATE\","
                        + "\"groupKey\":\"9269d3bfab6f44b147fb32311e149eb326f4a13f47538d5b8ce9223428ee9f6f\","
                        + "\"userKey\":null}",
                json);
    }

    @Test
    void replacesUnpairedSurrogatesToKeepUtf8Valid() {
        WebhookPayload payload = new WebhookPayload(
                "event-1", java.time.Instant.EPOCH, "bad\ud800value",
                "GROUP", "UPDATE", "route-key", null);

        String json = new String(payload.toJson(), StandardCharsets.UTF_8);
        assertTrue(json.contains("bad\\ufffdvalue"));
    }

    @Test
    void derivesOnlyAnOpaqueRoutingKeyFromTheCrossVersionAdminPath() {
        AdminEvent event = new AdminEvent();
        event.setTime(1_700_000_000_123L);
        event.setRealmId("realm-1");
        event.setRealmName("engineering");
        event.setResourceType(ResourceType.GROUP);
        event.setOperationType(OperationType.UPDATE);
        event.setResourcePath("groups/runtime-generated-id");

        final String json;
        try (RoutingKey routingKey = new RoutingKey(SECRET)) {
            json = new String(
                    WebhookPayload.from(event, "event-1", routingKey).toJson(),
                    StandardCharsets.UTF_8);
        }

        assertTrue(json.contains("\"groupKey\":"));
        assertTrue(!json.contains("runtime-generated-id"));
        assertTrue(!json.contains("resourcePath"));
        assertTrue(!json.contains("resourceId"));
    }

    @Test
    void emitsLoginHintWithoutClientSessionIpOrDetails() {
        Event event = new Event();
        event.setTime(1_700_000_000_123L);
        event.setRealmId("realm-1");
        event.setRealmName("engineering");
        event.setType(EventType.LOGIN);
        event.setUserId("user-1");
        event.setClientId("gitlab");
        event.setSessionId("private-session");
        event.setIpAddress("192.0.2.1");
        event.setDetails(java.util.Map.of("username", "private-user"));

        final String json;
        try (RoutingKey routingKey = new RoutingKey(SECRET)) {
            json = new String(
                    WebhookPayload.from(event, "event-1", routingKey).toJson(),
                    StandardCharsets.UTF_8);
        }

        assertEquals(
                "{\"specVersion\":\"1.0\",\"eventId\":\"event-1\","
                        + "\"occurredAt\":\"2023-11-14T22:13:20.123Z\","
                        + "\"realmName\":\"engineering\","
                        + "\"resourceType\":\"USER\",\"operationType\":\"LOGIN\","
                        + "\"groupKey\":null,"
                        + "\"userKey\":\"13fb297e65554f24569bb782175e6745c111cd5ed1ebbd740404db4d4b66e236\"}",
                json);
    }

    @Test
    void malformedAdminPathRequestsTopologyRepairWithoutLeakingThePath() {
        AdminEvent event = new AdminEvent();
        event.setTime(1_700_000_000_123L);
        event.setRealmName("engineering");
        event.setResourceType(ResourceType.GROUP);
        event.setOperationType(OperationType.CREATE);
        event.setResourcePath("groups/private/id");

        final String json;
        try (RoutingKey routingKey = new RoutingKey(SECRET)) {
            json = new String(
                    WebhookPayload.from(event, "event-1", routingKey).toJson(),
                    StandardCharsets.UTF_8);
        }

        assertTrue(json.contains("\"groupKey\":null"));
        assertTrue(!json.contains("private"));
    }

    @Test
    void directUserDeleteEmitsOnlyAPrivateUserRoutingKey() {
        AdminEvent event = new AdminEvent();
        event.setTime(1_700_000_000_123L);
        event.setRealmName("engineering");
        event.setResourceType(ResourceType.USER);
        event.setOperationType(OperationType.DELETE);
        event.setResourcePath("users/private-user-id");

        final String json;
        try (RoutingKey routingKey = new RoutingKey(SECRET)) {
            json = new String(
                    WebhookPayload.from(event, "event-1", routingKey).toJson(),
                    StandardCharsets.UTF_8);
        }

        assertTrue(json.contains("\"groupKey\":null"));
        assertTrue(json.contains(
                "\"userKey\":\"1ac5504a72c4b71c8377044145d8f48ec91bc9141188eef45794140332277008\""));
        assertTrue(!json.contains("private-user-id"));
    }
}
