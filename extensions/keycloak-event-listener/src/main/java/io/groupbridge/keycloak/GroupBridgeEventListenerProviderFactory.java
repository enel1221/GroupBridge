package io.groupbridge.keycloak;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class GroupBridgeEventListenerProviderFactory implements EventListenerProviderFactory {
    public static final String ID = "groupbridge";
    private AsyncWebhookDispatcher dispatcher;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        if (dispatcher == null) {
            throw new IllegalStateException("GroupBridge event listener is not initialized");
        }
        return new GroupBridgeEventListenerProvider(session, dispatcher);
    }

    @Override
    public void init(Config.Scope config) {
        ProviderConfiguration configuration = ProviderConfiguration.from(config::get);
        dispatcher = new AsyncWebhookDispatcher(new WebhookSender(configuration), configuration);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization required.
    }

    @Override
    public void close() {
        if (dispatcher != null) {
            dispatcher.close();
            dispatcher = null;
        }
    }

    @Override
    public String getId() {
        return ID;
    }
}
