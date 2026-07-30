package io.groupbridge.keycloak;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;

record WebhookPayload(
        String eventId,
        Instant occurredAt,
        String realmName,
        String resourceType,
        String operationType,
        String groupKey,
        String userKey) {

    private static final String SPEC_VERSION = "1.0";

    static WebhookPayload from(AdminEvent event, String deliveryId, RoutingKey routingKey) {
        String operationType = event.getOperationType() == null ? null : event.getOperationType().name();
        String resourceType = event.getResourceTypeAsString();
        String groupId = groupId(resourceType, event.getResourcePath());
        String userId = userId(resourceType, event.getResourcePath());
        return new WebhookPayload(
                deliveryId,
                Instant.ofEpochMilli(event.getTime()),
                event.getRealmName(),
                resourceType,
                operationType,
                routingKey.group(event.getRealmName(), groupId),
                routingKey.user(event.getRealmName(), userId));
    }

    static WebhookPayload from(Event event, String deliveryId, RoutingKey routingKey) {
        String operationType = event.getType() == null ? null : event.getType().name();
        return new WebhookPayload(
                deliveryId,
                Instant.ofEpochMilli(event.getTime()),
                event.getRealmName(),
                "USER",
                operationType,
                null,
                routingKey.user(event.getRealmName(), event.getUserId()));
    }

    byte[] toJson() {
        StringBuilder json = new StringBuilder(384);
        json.append('{');
        field(json, "specVersion", SPEC_VERSION);
        json.append(',');
        field(json, "eventId", eventId);
        json.append(',');
        field(json, "occurredAt", occurredAt.toString());
        json.append(',');
        field(json, "realmName", realmName);
        json.append(',');
        field(json, "resourceType", resourceType);
        json.append(',');
        field(json, "operationType", operationType);
        json.append(',');
        field(json, "groupKey", groupKey);
        json.append(',');
        field(json, "userKey", userKey);
        json.append('}');
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String groupId(String resourceType, String resourcePath) {
        if (resourcePath == null) {
            return null;
        }
        String[] segments = resourcePath.split("/", -1);
        if ("GROUP".equals(resourceType)
                && segments.length == 2
                && "groups".equals(segments[0])
                && !segments[1].isBlank()) {
            return segments[1];
        }
        if (("GROUP_MEMBERSHIP".equals(resourceType) || "USER".equals(resourceType))
                && segments.length == 4
                && "users".equals(segments[0])
                && !segments[1].isBlank()
                && "groups".equals(segments[2])
                && !segments[3].isBlank()) {
            return segments[3];
        }
        return null;
    }

    private static String userId(String resourceType, String resourcePath) {
        if (!"USER".equals(resourceType) || resourcePath == null) {
            return null;
        }
        String[] segments = resourcePath.split("/", -1);
        if (segments.length == 2
                && "users".equals(segments[0])
                && !segments[1].isBlank()) {
            return segments[1];
        }
        return null;
    }

    private static void field(StringBuilder json, String name, String value) {
        string(json, name);
        json.append(':');
        if (value == null) {
            json.append("null");
        } else {
            string(json, value);
        }
    }

    private static void string(StringBuilder json, String value) {
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> appendCharacter(json, value, index, character);
            }
            if (Character.isHighSurrogate(character)
                    && index + 1 < value.length()
                    && Character.isLowSurrogate(value.charAt(index + 1))) {
                index++;
            }
        }
        json.append('"');
    }

    private static void appendCharacter(StringBuilder json, String value, int index, char character) {
        if (character < 0x20) {
            appendUnicodeEscape(json, character);
            return;
        }
        if (Character.isHighSurrogate(character)) {
            if (index + 1 < value.length() && Character.isLowSurrogate(value.charAt(index + 1))) {
                json.append(character).append(value.charAt(index + 1));
            } else {
                json.append("\\ufffd");
            }
            return;
        }
        if (Character.isLowSurrogate(character)) {
            json.append("\\ufffd");
            return;
        }
        json.append(character);
    }

    private static void appendUnicodeEscape(StringBuilder json, char character) {
        json.append("\\u");
        String hexadecimal = Integer.toHexString(character);
        json.append("0".repeat(4 - hexadecimal.length())).append(hexadecimal);
    }
}
