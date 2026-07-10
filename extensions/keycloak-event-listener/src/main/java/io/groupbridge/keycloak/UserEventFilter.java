package io.groupbridge.keycloak;

import org.keycloak.events.Event;
import org.keycloak.events.EventType;

final class UserEventFilter {
    private UserEventFilter() {
    }

    static boolean isRelevant(Event event) {
        return event != null
                && event.getError() == null
                && (event.getType() == EventType.LOGIN || event.getType() == EventType.REGISTER);
    }
}
