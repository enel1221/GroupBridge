package io.groupbridge.keycloak;

import java.util.Set;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

final class GroupBridgeEventListenerProvider implements EventListenerProvider {
    private final HintTransaction transaction;
    private final Set<String> jitClientIds;
    private final RoutingKey routingKey;

    GroupBridgeEventListenerProvider(
            KeycloakSession session,
            AsyncWebhookDispatcher dispatcher,
            Set<String> jitClientIds,
            RoutingKey routingKey) {
        this.transaction = new HintTransaction(dispatcher);
        this.jitClientIds = Set.copyOf(jitClientIds);
        this.routingKey = routingKey;
        session.getTransactionManager().enlistAfterCompletion(transaction);
    }

    @Override
    public void onEvent(Event event) {
        if (UserEventFilter.isRelevant(event, jitClientIds)) {
            transaction.add(WebhookHint.from(event, routingKey));
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (AdminEventFilter.isRelevant(event)) {
            // The transaction helper invokes the sender only after a successful commit.
            // Representation is deliberately excluded from the GroupBridge payload.
            transaction.add(WebhookHint.from(event, routingKey));
        }
    }

    @Override
    public void close() {
        // The per-session provider owns no resources. The factory owns the HTTP client/secret.
    }
}
