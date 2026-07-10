package io.groupbridge.keycloak;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.models.AbstractKeycloakTransaction;

final class HintTransaction extends AbstractKeycloakTransaction {
    private final AsyncWebhookDispatcher dispatcher;
    private final List<WebhookHint> hints = new ArrayList<>();

    HintTransaction(AsyncWebhookDispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    void add(WebhookHint hint) {
        hints.add(hint);
    }

    @Override
    protected void commitImpl() {
        hints.forEach(dispatcher::submit);
        hints.clear();
    }

    @Override
    protected void rollbackImpl() {
        hints.clear();
    }
}
