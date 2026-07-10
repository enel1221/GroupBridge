package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ProviderConfigurationTest {
    private static final String SECRET = "0123456789abcdef0123456789abcdef";

    @Test
    void appliesSecureDefaults() {
        ProviderConfiguration configuration = ProviderConfiguration.from(Map.of(
                "webhook-url", "https://groupbridge.example.test/v1/events/keycloak",
                "webhook-secret", SECRET)::get);

        assertEquals("https", configuration.webhookUrl().getScheme());
        assertEquals(Duration.ofSeconds(2), configuration.connectTimeout());
        assertEquals(Duration.ofSeconds(3), configuration.requestTimeout());
        assertEquals(2, configuration.workerThreads());
        assertEquals(256, configuration.queueCapacity());
        assertEquals(Duration.ofSeconds(2), configuration.shutdownTimeout());
    }

    @Test
    void rejectsPlainHttpByDefault() {
        Map<String, String> values = Map.of(
                "webhook-url", "http://groupbridge.test/v1/events/keycloak",
                "webhook-secret", SECRET);

        assertThrows(IllegalArgumentException.class,
                () -> ProviderConfiguration.from(values::get));
    }

    @Test
    void permitsExplicitLocalHttpAndCustomTimeouts() {
        ProviderConfiguration configuration = ProviderConfiguration.from(Map.of(
                "webhook-url", "http://groupbridge.test/v1/events/keycloak",
                "webhook-secret", SECRET,
                "allow-insecure-http", "true",
                "connect-timeout-ms", "125",
                "request-timeout-ms", "250",
                "worker-threads", "1",
                "queue-capacity", "32",
                "shutdown-timeout-ms", "500")::get);

        assertEquals(Duration.ofMillis(125), configuration.connectTimeout());
        assertEquals(Duration.ofMillis(250), configuration.requestTimeout());
        assertEquals(1, configuration.workerThreads());
        assertEquals(32, configuration.queueCapacity());
        assertEquals(Duration.ofMillis(500), configuration.shutdownTimeout());
    }

    @Test
    void rejectsCredentialsInUrlAndWeakSecret() {
        Map<String, String> credentialUrl = Map.of(
                "webhook-url", "https://user:password@groupbridge.test/v1/events/keycloak",
                "webhook-secret", SECRET);
        assertThrows(IllegalArgumentException.class,
                () -> ProviderConfiguration.from(credentialUrl::get));

        Map<String, String> weakSecret = Map.of(
                "webhook-url", "https://groupbridge.test/v1/events/keycloak",
                "webhook-secret", "too-short");
        assertThrows(IllegalArgumentException.class,
                () -> ProviderConfiguration.from(weakSecret::get));
    }

    @Test
    void validatesBooleanAndTimeoutBounds() {
        Map<String, String> values = new HashMap<>();
        values.put("webhook-url", "https://groupbridge.test/v1/events/keycloak");
        values.put("webhook-secret", SECRET);
        values.put("allow-insecure-http", "sometimes");
        assertThrows(IllegalArgumentException.class,
                () -> ProviderConfiguration.from(values::get));

        values.remove("allow-insecure-http");
        values.put("request-timeout-ms", "30001");
        assertThrows(IllegalArgumentException.class,
                () -> ProviderConfiguration.from(values::get));
    }

    @Test
    void doesNotExposeMutableSecret() {
        ProviderConfiguration configuration = ProviderConfiguration.from(Map.of(
                "webhook-url", "https://groupbridge.test/v1/events/keycloak",
                "webhook-secret", SECRET)::get);

        byte[] first = configuration.webhookSecret();
        first[0] = 0;
        assertNotEquals(0, configuration.webhookSecret()[0]);
    }
}
