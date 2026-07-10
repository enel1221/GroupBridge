package io.groupbridge.keycloak;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

final class GroupBridgeEventListenerProvider implements EventListenerProvider {
    private final HintTransaction transaction;

    GroupBridgeEventListenerProvider(KeycloakSession session, AsyncWebhookDispatcher dispatcher) {
        this.transaction = new HintTransaction(dispatcher);
        session.getTransactionManager().enlistAfterCompletion(transaction);
    }

    @Override
    public void onEvent(Event event) {
        if (UserEventFilter.isRelevant(event)) {
            transaction.add(WebhookHint.from(event));
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (AdminEventFilter.isRelevant(event)) {
            // The transaction helper invokes the sender only after a successful commit.
            // Representation is deliberately excluded from the GroupBridge payload.
            transaction.add(WebhookHint.from(event));
        }
    }

    @Override
    public void close() {
        // The per-session provider owns no resources. The factory owns the HTTP client/secret.
    }
}
