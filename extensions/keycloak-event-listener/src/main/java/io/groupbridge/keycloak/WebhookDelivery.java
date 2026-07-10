package io.groupbridge.keycloak;

interface WebhookDelivery extends AutoCloseable {
    boolean deliver(WebhookHint hint);

    @Override
    default void close() {
        // Most test/fake deliveries own no resources.
    }
}
