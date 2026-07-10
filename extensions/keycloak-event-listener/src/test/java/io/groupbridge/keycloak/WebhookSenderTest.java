package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.KeycloakTransactionManager;

class WebhookSenderTest {
    private static final String SECRET = "0123456789abcdef0123456789abcdef";
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void postsSignedJsonAndAcceptsAnyTwoHundredResponse() throws Exception {
        AtomicReference<CapturedRequest> captured = new AtomicReference<>();
        start(exchange -> {
            captured.set(new CapturedRequest(
                    exchange.getRequestHeaders().getFirst("X-GroupBridge-Timestamp"),
                    exchange.getRequestHeaders().getFirst("X-GroupBridge-Delivery"),
                    exchange.getRequestHeaders().getFirst("X-GroupBridge-Signature"),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });

        try (WebhookSender sender = sender()) {
            assertTrue(sender.deliver(WebhookHint.from(event(), () -> "delivery-fixed")));
        }

        CapturedRequest request = captured.get();
        assertEquals("1700000000", request.timestamp());
        assertEquals("delivery-fixed", request.delivery());
        assertEquals(
                WebhookSigner.sign(
                        SECRET.getBytes(StandardCharsets.UTF_8),
                        1_700_000_000L,
                        "delivery-fixed",
                        request.body().getBytes(StandardCharsets.UTF_8)),
                request.signature());
        assertTrue(request.body().contains("\"eventId\":\"delivery-fixed\""));
        assertFalse(request.body().contains("representation"));
    }

    @Test
    void returnsFalseForNonSuccessWithoutReadingResponseBody() throws Exception {
        start(exchange -> {
            exchange.sendResponseHeaders(503, 0);
            exchange.close();
        });

        try (WebhookSender sender = sender()) {
            assertFalse(sender.deliver(WebhookHint.from(event(), () -> "delivery-fixed")));
        }
    }

    @Test
    void providerDeliversOnlyAfterTransactionCommit() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch releaseResponse = new CountDownLatch(1);
        CountDownLatch delivered = new CountDownLatch(1);
        start(exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            requestStarted.countDown();
            try {
                releaseResponse.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
            delivered.countDown();
        });
        AtomicReference<KeycloakTransaction> enlisted = new AtomicReference<>();

        try (AsyncWebhookDispatcher dispatcher = new AsyncWebhookDispatcher(
                sender(), 1, 8, java.time.Duration.ofSeconds(1))) {
            GroupBridgeEventListenerProvider provider = new GroupBridgeEventListenerProvider(
                    sessionCapturing(enlisted), dispatcher);
            provider.onEvent(event(), true);

            assertNull(body.get());
            assertTimeoutPreemptively(
                    java.time.Duration.ofMillis(250), enlisted.get()::commit);
            assertTrue(requestStarted.await(1, TimeUnit.SECONDS));
            releaseResponse.countDown();
            assertTrue(delivered.await(1, TimeUnit.SECONDS));
            assertTrue(body.get().contains("\"resourceType\":\"GROUP\""));
        } finally {
            releaseResponse.countDown();
        }
    }

    @Test
    void providerQueuesSuccessfulLoginAsMetadataOnlyHint() throws Exception {
        AtomicReference<WebhookHint> captured = new AtomicReference<>();
        CountDownLatch delivered = new CountDownLatch(1);
        WebhookDelivery delivery = hint -> {
            captured.set(hint);
            delivered.countDown();
            return true;
        };
        AtomicReference<KeycloakTransaction> enlisted = new AtomicReference<>();

        try (AsyncWebhookDispatcher dispatcher = new AsyncWebhookDispatcher(
                delivery, 1, 8, java.time.Duration.ofSeconds(1))) {
            GroupBridgeEventListenerProvider provider = new GroupBridgeEventListenerProvider(
                    sessionCapturing(enlisted), dispatcher);
            provider.onEvent(loginEvent());

            assertNull(captured.get());
            enlisted.get().commit();
            assertTrue(delivered.await(1, TimeUnit.SECONDS));
            assertEquals("LOGIN", captured.get().payload().operationType());
            assertEquals("USER", captured.get().payload().resourceType());
            assertNull(captured.get().payload().resourceId());
            assertNull(captured.get().payload().resourcePath());
        }
    }

    private WebhookSender sender() {
        ProviderConfiguration configuration = ProviderConfiguration.from(Map.of(
                "webhook-url", "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/events/keycloak",
                "webhook-secret", SECRET,
                "allow-insecure-http", "true")::get);
        return new WebhookSender(
                configuration,
                HttpClient.newBuilder().connectTimeout(configuration.connectTimeout()).build(),
                Clock.fixed(Instant.ofEpochSecond(1_700_000_000L), ZoneOffset.UTC));
    }

    private static AdminEvent event() {
        AdminEvent event = new AdminEvent();
        event.setTime(1_700_000_000_123L);
        event.setRealmId("realm-1");
        event.setRealmName("engineering");
        event.setResourceType(ResourceType.GROUP);
        event.setOperationType(OperationType.UPDATE);
        event.setResourcePath("groups/group-1");
        return event;
    }

    private static Event loginEvent() {
        Event event = new Event();
        event.setId("login-event-1");
        event.setTime(1_700_000_000_123L);
        event.setRealmId("realm-1");
        event.setRealmName("engineering");
        event.setType(EventType.LOGIN);
        event.setUserId("private-user-id");
        event.setIpAddress("192.0.2.1");
        return event;
    }

    private void start(ExchangeHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/events/keycloak", handler::handle);
        server.start();
    }

    private static KeycloakSession sessionCapturing(AtomicReference<KeycloakTransaction> enlisted) {
        KeycloakTransactionManager transactionManager = (KeycloakTransactionManager) Proxy.newProxyInstance(
                KeycloakTransactionManager.class.getClassLoader(),
                new Class<?>[] {KeycloakTransactionManager.class},
                (proxy, method, arguments) -> {
                    if ("enlistAfterCompletion".equals(method.getName())) {
                        KeycloakTransaction transaction = (KeycloakTransaction) arguments[0];
                        transaction.begin();
                        enlisted.set(transaction);
                    }
                    if (method.getReturnType() == boolean.class) {
                        return false;
                    }
                    return null;
                });
        return (KeycloakSession) Proxy.newProxyInstance(
                KeycloakSession.class.getClassLoader(),
                new Class<?>[] {KeycloakSession.class},
                (proxy, method, arguments) -> {
                    if ("getTransactionManager".equals(method.getName())) {
                        return transactionManager;
                    }
                    if (method.getReturnType() == boolean.class) {
                        return false;
                    }
                    return null;
                });
    }

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private record CapturedRequest(String timestamp, String delivery, String signature, String body) {
    }
}
