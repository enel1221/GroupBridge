package io.groupbridge.keycloak;

import java.util.Arrays;
import java.util.Set;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class GroupBridgeEventListenerProviderFactory implements EventListenerProviderFactory {
    public static final String ID = "groupbridge";
    private AsyncWebhookDispatcher dispatcher;
    private Set<String> jitClientIds = Set.of();
    private RoutingKey routingKey;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        if (dispatcher == null) {
            throw new IllegalStateException("GroupBridge event listener is not initialized");
        }
        return new GroupBridgeEventListenerProvider(session, dispatcher, jitClientIds, routingKey);
    }

    @Override
    public void init(Config.Scope config) {
        ProviderConfiguration configuration = ProviderConfiguration.from(config::get);
        dispatcher = new AsyncWebhookDispatcher(new WebhookSender(configuration), configuration);
        jitClientIds = configuration.jitClientIds();
        byte[] secret = configuration.webhookSecret();
        try {
            routingKey = new RoutingKey(secret);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
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
        if (routingKey != null) {
            routingKey.close();
            routingKey = null;
        }
        jitClientIds = Set.of();
    }

    @Override
    public String getId() {
        return ID;
    }
}
