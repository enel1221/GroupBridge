package io.groupbridge.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class WebhookSigner {
    private static final String HMAC_SHA_256 = "HmacSHA256";

    private WebhookSigner() {
    }

    static String sign(byte[] secret, long timestamp, String deliveryId, byte[] body) {
        try {
            Mac hmac = Mac.getInstance(HMAC_SHA_256);
            hmac.init(new SecretKeySpec(secret, HMAC_SHA_256));
            hmac.update(Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII));
            hmac.update((byte) '\n');
            hmac.update(deliveryId.getBytes(StandardCharsets.UTF_8));
            hmac.update((byte) '\n');
            return "sha256=" + java.util.HexFormat.of().formatHex(hmac.doFinal(body));
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HmacSHA256 is unavailable", error);
        }
    }
}
