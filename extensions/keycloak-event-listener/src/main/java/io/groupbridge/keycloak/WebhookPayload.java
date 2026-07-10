package io.groupbridge.keycloak;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;

record WebhookPayload(
        String eventId,
        Instant occurredAt,
        String realmId,
        String realmName,
        String resourceType,
        String operationType,
        String resourcePath,
        String resourceId) {

    private static final String SPEC_VERSION = "1.0";

    static WebhookPayload from(AdminEvent event, String deliveryId) {
        String operationType = event.getOperationType() == null ? null : event.getOperationType().name();
        return new WebhookPayload(
                deliveryId,
                Instant.ofEpochMilli(event.getTime()),
                event.getRealmId(),
                event.getRealmName(),
                event.getResourceTypeAsString(),
                operationType,
                event.getResourcePath(),
                event.getResourceId());
    }

    static WebhookPayload from(Event event, String deliveryId) {
        String operationType = event.getType() == null ? null : event.getType().name();
        return new WebhookPayload(
                deliveryId,
                Instant.ofEpochMilli(event.getTime()),
                event.getRealmId(),
                event.getRealmName(),
                "USER",
                operationType,
                null,
                null);
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
        field(json, "realmId", realmId);
        json.append(',');
        field(json, "realmName", realmName);
        json.append(',');
        field(json, "resourceType", resourceType);
        json.append(',');
        field(json, "operationType", operationType);
        json.append(',');
        field(json, "resourcePath", resourcePath);
        json.append(',');
        field(json, "resourceId", resourceId);
        json.append('}');
        return json.toString().getBytes(StandardCharsets.UTF_8);
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
