package io.groupbridge.keycloak;

import org.keycloak.events.admin.AdminEvent;

final class AdminEventFilter {
    private static final String GROUP = "GROUP";
    private static final String GROUP_MEMBERSHIP = "GROUP_MEMBERSHIP";
    private static final String USER = "USER";

    private AdminEventFilter() {
    }

    static boolean isRelevant(AdminEvent event) {
        if (event == null || event.getError() != null) {
            return false;
        }

        String resourceType = event.getResourceTypeAsString();
        if (GROUP.equals(resourceType) || GROUP_MEMBERSHIP.equals(resourceType)) {
            return true;
        }

        // Some Keycloak admin endpoints classify a membership mutation as USER.
        return USER.equals(resourceType) && isUserGroupMembershipPath(event.getResourcePath());
    }

    private static boolean isUserGroupMembershipPath(String resourcePath) {
        if (resourcePath == null) {
            return false;
        }
        String[] segments = resourcePath.split("/", -1);
        return segments.length == 4
                && "users".equals(segments[0])
                && !segments[1].isBlank()
                && "groups".equals(segments[2])
                && !segments[3].isBlank();
    }
}
