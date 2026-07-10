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

        String json = new String(WebhookPayload.from(event, "event-1").toJson(), StandardCharsets.UTF_8);

        assertEquals(
                "{\"specVersion\":\"1.0\",\"eventId\":\"event-1\","
                        + "\"occurredAt\":\"2023-11-14T22:13:20.123Z\","
                        + "\"realmId\":\"realm-1\",\"realmName\":\"engineering\\n\\\"east\\\"\","
                        + "\"resourceType\":\"GROUP_MEMBERSHIP\",\"operationType\":\"CREATE\","
                        + "\"resourcePath\":\"users/user-1/groups/group-1\",\"resourceId\":\"group-1\"}",
                json);
    }

    @Test
    void replacesUnpairedSurrogatesToKeepUtf8Valid() {
        WebhookPayload payload = new WebhookPayload(
                "event-1", java.time.Instant.EPOCH, "realm", "bad\ud800value",
                "GROUP", "UPDATE", "groups/group-1", "group-1");

        String json = new String(payload.toJson(), StandardCharsets.UTF_8);
        assertTrue(json.contains("bad\\ufffdvalue"));
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

        String json = new String(WebhookPayload.from(event, "event-1").toJson(), StandardCharsets.UTF_8);

        assertEquals(
                "{\"specVersion\":\"1.0\",\"eventId\":\"event-1\","
                        + "\"occurredAt\":\"2023-11-14T22:13:20.123Z\","
                        + "\"realmId\":\"realm-1\",\"realmName\":\"engineering\","
                        + "\"resourceType\":\"USER\",\"operationType\":\"LOGIN\","
                        + "\"resourcePath\":null,\"resourceId\":null}",
                json);
    }
}
