package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
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
    void acceptsDirectUserUpdateAndDeleteButNotCreate() {
        AdminEvent update = event(ResourceType.USER, "users/user-1");
        update.setOperationType(OperationType.UPDATE);
        assertTrue(AdminEventFilter.isRelevant(update));
        AdminEvent delete = event(ResourceType.USER, "users/user-1");
        delete.setOperationType(OperationType.DELETE);
        assertTrue(AdminEventFilter.isRelevant(delete));
        AdminEvent create = event(ResourceType.USER, "users/user-1");
        create.setOperationType(OperationType.CREATE);
        assertFalse(AdminEventFilter.isRelevant(create));
    }

    @Test
    void rejectsFailedAdminEvents() {
        AdminEvent event = event(ResourceType.GROUP, "groups/group-1");
        event.setError("forbidden");
        assertFalse(AdminEventFilter.isRelevant(event));
    }

    @Test
    void rejectsUnsupportedGroupActions() {
        AdminEvent event = event(ResourceType.GROUP, "groups/group-1");
        event.setOperationType(OperationType.ACTION);
        assertFalse(AdminEventFilter.isRelevant(event));
    }

    private static AdminEvent event(ResourceType type, String path) {
        AdminEvent event = new AdminEvent();
        event.setResourceType(type);
        event.setResourcePath(path);
        event.setOperationType(OperationType.CREATE);
        return event;
    }
}
