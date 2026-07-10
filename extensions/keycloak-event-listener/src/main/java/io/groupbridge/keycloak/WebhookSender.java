package io.groupbridge.keycloak;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;

final class WebhookSender implements WebhookDelivery {
    private static final System.Logger LOGGER = System.getLogger(WebhookSender.class.getName());
    private static final String USER_AGENT = "GroupBridge-Keycloak-Listener/1";

    private final URI webhookUrl;
    private final Duration requestTimeout;
    private final HttpClient client;
    private final Clock clock;
    private final byte[] secret;

    WebhookSender(ProviderConfiguration configuration) {
        this(
                configuration,
                HttpClient.newBuilder()
                        .connectTimeout(configuration.connectTimeout())
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .version(HttpClient.Version.HTTP_1_1)
                        .build(),
                Clock.systemUTC());
    }

    WebhookSender(
            ProviderConfiguration configuration,
            HttpClient client,
            Clock clock) {
        this.webhookUrl = configuration.webhookUrl();
        this.requestTimeout = configuration.requestTimeout();
        this.client = client;
        this.clock = clock;
        this.secret = configuration.webhookSecret();
    }

    public boolean deliver(WebhookHint hint) {
        String deliveryId = hint.deliveryId();
        long timestamp = clock.instant().getEpochSecond();
        byte[] body = hint.payload().toJson();

        HttpRequest request = HttpRequest.newBuilder(webhookUrl)
                .timeout(requestTimeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", USER_AGENT)
                .header("X-GroupBridge-Timestamp", Long.toString(timestamp))
                .header("X-GroupBridge-Delivery", deliveryId)
                .header("X-GroupBridge-Signature", WebhookSigner.sign(secret, timestamp, deliveryId, body))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        try {
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                LOGGER.log(System.Logger.Level.DEBUG,
                        "GroupBridge webhook delivered: delivery={0}, status={1}",
                        deliveryId, response.statusCode());
                return true;
            }
            LOGGER.log(System.Logger.Level.WARNING,
                    "GroupBridge webhook rejected: delivery={0}, status={1}",
                    deliveryId, response.statusCode());
            return false;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            LOGGER.log(System.Logger.Level.WARNING,
                    "GroupBridge webhook interrupted: delivery={0}", deliveryId);
            return false;
        } catch (IOException | RuntimeException error) {
            // Log only the exception class: messages can include the configured URL.
            LOGGER.log(System.Logger.Level.WARNING,
                    "GroupBridge webhook failed: delivery={0}, cause={1}",
                    deliveryId, error.getClass().getSimpleName());
            return false;
        }
    }

    @Override
    public void close() {
        client.shutdownNow();
        Arrays.fill(secret, (byte) 0);
    }
}
