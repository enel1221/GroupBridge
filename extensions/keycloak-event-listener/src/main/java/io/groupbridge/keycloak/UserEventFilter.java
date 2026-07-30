package io.groupbridge.keycloak;

import java.util.Set;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

final class UserEventFilter {
    private UserEventFilter() {
    }

    static boolean isRelevant(Event event, Set<String> jitClientIds) {
        return event != null
                && event.getError() == null
                && event.getType() == EventType.LOGIN
                && event.getClientId() != null
                && jitClientIds.contains(event.getClientId());
    }
}
