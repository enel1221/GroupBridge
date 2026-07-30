package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

class UserEventFilterTest {
    @Test
    void acceptsOnlySuccessfulLoginForAnAllowlistedClient() {
        assertTrue(UserEventFilter.isRelevant(
                event(EventType.LOGIN, "gitlab", null),
                Set.of("gitlab")));
    }

    @Test
    void rejectsEmptyOrWrongClientErrorsRegistrationAndUnrelatedEvents() {
        assertFalse(UserEventFilter.isRelevant(
                event(EventType.LOGIN, "gitlab", null),
                Set.of()));
        assertFalse(UserEventFilter.isRelevant(
                event(EventType.LOGIN, "hub-ui", null),
                Set.of("gitlab")));
        assertFalse(UserEventFilter.isRelevant(
                event(EventType.LOGIN_ERROR, "gitlab", "invalid_user_credentials"),
                Set.of("gitlab")));
        assertFalse(UserEventFilter.isRelevant(
                event(EventType.REGISTER, "gitlab", null),
                Set.of("gitlab")));
        assertFalse(UserEventFilter.isRelevant(
                event(EventType.UPDATE_PROFILE, "gitlab", null),
                Set.of("gitlab")));
        assertFalse(UserEventFilter.isRelevant(null, Set.of("gitlab")));
    }

    private static Event event(EventType type, String clientId, String error) {
        Event event = new Event();
        event.setType(type);
        event.setClientId(clientId);
        event.setError(error);
        return event;
    }
}
