package io.groupbridge.keycloak;

import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.keycloak.events.Event;
import org.keycloak.events.admin.AdminEvent;

record WebhookHint(String deliveryId, WebhookPayload payload) {
    private static final int MAX_DELIVERY_ID_LENGTH = 128;

    WebhookHint {
        Objects.requireNonNull(deliveryId, "deliveryId");
        Objects.requireNonNull(payload, "payload");
    }

    static WebhookHint from(AdminEvent event) {
        return from(event, () -> UUID.randomUUID().toString());
    }

    static WebhookHint from(AdminEvent event, Supplier<String> deliveryIdSupplier) {
        String deliveryId = deliveryId(event.getId(), deliveryIdSupplier);
        return new WebhookHint(deliveryId, WebhookPayload.from(event, deliveryId));
    }

    static WebhookHint from(Event event) {
        return from(event, () -> UUID.randomUUID().toString());
    }

    static WebhookHint from(Event event, Supplier<String> deliveryIdSupplier) {
        String deliveryId = deliveryId(event.getId(), deliveryIdSupplier);
        return new WebhookHint(deliveryId, WebhookPayload.from(event, deliveryId));
    }

    private static String deliveryId(String eventId, Supplier<String> deliveryIdSupplier) {
        if (isSafe(eventId)) {
            return eventId;
        }
        String generated = deliveryIdSupplier.get();
        if (!isSafe(generated)) {
            throw new IllegalArgumentException("generated delivery ID is invalid");
        }
        return generated;
    }

    private static boolean isSafe(String value) {
        if (value == null || value.isEmpty() || value.length() > MAX_DELIVERY_ID_LENGTH) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(character >= 'A' && character <= 'Z')
                    && !(character >= 'a' && character <= 'z')
                    && !(character >= '0' && character <= '9')
                    && character != '.' && character != '_' && character != ':' && character != '-') {
                return false;
            }
        }
        return true;
    }
}
