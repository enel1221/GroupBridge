package io.groupbridge.keycloak;

import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;

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
        if (GROUP.equals(resourceType)) {
            return event.getOperationType() == OperationType.CREATE
                    || event.getOperationType() == OperationType.UPDATE
                    || event.getOperationType() == OperationType.DELETE;
        }
        if (GROUP_MEMBERSHIP.equals(resourceType)) {
            return event.getOperationType() == OperationType.CREATE
                    || event.getOperationType() == OperationType.DELETE;
        }

        if (!USER.equals(resourceType)) {
            return false;
        }
        // Some Keycloak admin endpoints classify a membership mutation as USER.
        if (isUserGroupMembershipPath(event.getResourcePath())) {
            return true;
        }
        // A direct user disable/update/delete can affect every managed group the
        // user belonged to. Route it by a private user HMAC so the receiver can
        // authoritatively re-read only those previously indexed groups.
        return isDirectUserPath(event.getResourcePath())
                && (event.getOperationType() == OperationType.UPDATE
                        || event.getOperationType() == OperationType.DELETE);
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

    private static boolean isDirectUserPath(String resourcePath) {
        if (resourcePath == null) {
            return false;
        }
        String[] segments = resourcePath.split("/", -1);
        return segments.length == 2
                && "users".equals(segments[0])
                && !segments[1].isBlank();
    }
}
