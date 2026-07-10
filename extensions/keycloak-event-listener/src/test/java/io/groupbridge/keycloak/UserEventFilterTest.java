package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

class UserEventFilterTest {
    @Test
    void acceptsSuccessfulLoginAndRegistration() {
        assertTrue(UserEventFilter.isRelevant(event(EventType.LOGIN, null)));
        assertTrue(UserEventFilter.isRelevant(event(EventType.REGISTER, null)));
    }

    @Test
    void rejectsErrorsAndUnrelatedUserEvents() {
        assertFalse(UserEventFilter.isRelevant(event(EventType.LOGIN_ERROR, "invalid_user_credentials")));
        assertFalse(UserEventFilter.isRelevant(event(EventType.UPDATE_PROFILE, null)));
        assertFalse(UserEventFilter.isRelevant(null));
    }

    private static Event event(EventType type, String error) {
        Event event = new Event();
        event.setType(type);
        event.setError(error);
        return event;
    }
}
