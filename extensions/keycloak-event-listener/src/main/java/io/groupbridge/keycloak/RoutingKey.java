package io.groupbridge.keycloak;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class RoutingKey implements AutoCloseable {
    private static final String ALGORITHM = "HmacSHA256";
    private static final String VERSION = "groupbridge-route-v1";

    private final byte[] secret;

    RoutingKey(byte[] secret) {
        this.secret = secret.clone();
    }

    String group(String realmName, String groupId) {
        return key("group", realmName, groupId);
    }

    String user(String realmName, String userId) {
        return key("user", realmName, userId);
    }

    private String key(String domain, String realmName, String identifier) {
        if (realmName == null || realmName.isBlank() || identifier == null || identifier.isBlank()) {
            return null;
        }
        byte[] input = (VERSION + "\n" + domain + "\n" + realmName + "\n" + identifier)
                .getBytes(StandardCharsets.UTF_8);
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret, ALGORITHM));
            return HexFormat.of().formatHex(mac.doFinal(input));
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HMAC-SHA-256 is unavailable", error);
        } finally {
            Arrays.fill(input, (byte) 0);
        }
    }

    @Override
    public void close() {
        Arrays.fill(secret, (byte) 0);
    }
}
