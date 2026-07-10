package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class WebhookSignerTest {
    @Test
    void signsTimestampDeliveryAndExactBody() {
        String signature = WebhookSigner.sign(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8),
                1_700_000_000L,
                "delivery-1",
                "{}".getBytes(StandardCharsets.UTF_8));

        assertEquals(
                "sha256=81d2149ea2b657e77bb7ecdb1562be84303c7f083129385a7e7842b693f0f56f",
                signature);
    }
}
