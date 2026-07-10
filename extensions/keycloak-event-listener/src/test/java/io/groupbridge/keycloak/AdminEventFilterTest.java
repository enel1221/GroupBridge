package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.ResourceType;

class AdminEventFilterTest {
    @Test
    void acceptsGroupsAndNativeMemberships() {
        assertTrue(AdminEventFilter.isRelevant(event(ResourceType.GROUP, "groups/group-1")));
        assertTrue(AdminEventFilter.isRelevant(event(
                ResourceType.GROUP_MEMBERSHIP, "users/user-1/groups/group-1")));
    }

    @Test
    void acceptsMembershipPathReportedAsUser() {
        assertTrue(AdminEventFilter.isRelevant(event(
                ResourceType.USER, "users/user-1/groups/group-1")));
    }

    @Test
    void rejectsUnrelatedUserAndMalformedPaths() {
        assertFalse(AdminEventFilter.isRelevant(event(ResourceType.USER, "users/user-1")));
        assertFalse(AdminEventFilter.isRelevant(event(ResourceType.USER, "users//groups/group-1")));
        assertFalse(AdminEventFilter.isRelevant(event(ResourceType.USER, "users/user-1/groups/")));
        assertFalse(AdminEventFilter.isRelevant(event(ResourceType.CLIENT, "clients/client-1")));
    }

    @Test
    void rejectsFailedAdminEvents() {
        AdminEvent event = event(ResourceType.GROUP, "groups/group-1");
        event.setError("forbidden");
        assertFalse(AdminEventFilter.isRelevant(event));
    }

    private static AdminEvent event(ResourceType type, String path) {
        AdminEvent event = new AdminEvent();
        event.setResourceType(type);
        event.setResourcePath(path);
        return event;
    }
}
