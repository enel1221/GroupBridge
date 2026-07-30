package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class RoutingKeyTest {
    private static final byte[] SECRET =
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    void matchesTheCrossLanguageDomainSeparatedVectors() {
        try (RoutingKey routingKey = new RoutingKey(SECRET)) {
            assertEquals(
                    "992eada7c9836ee842f75dc1ab1d9cf872e61bb5d6536a87c2bb52cab6a8a8a0",
                    routingKey.group("engineering", "group-1"));
            assertEquals(
                    "1ac5504a72c4b71c8377044145d8f48ec91bc9141188eef45794140332277008",
                    routingKey.user("engineering", "private-user-id"));
            assertNotEquals(
                    routingKey.group("engineering", "private-user-id"),
                    routingKey.user("engineering", "private-user-id"));
        }
    }
}
