package io.groupbridge.keycloak;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;

record ProviderConfiguration(
        URI webhookUrl,
        byte[] webhookSecret,
        Duration connectTimeout,
        Duration requestTimeout,
        int workerThreads,
        int queueCapacity,
        Duration shutdownTimeout) {

    private static final int MIN_SECRET_BYTES = 32;
    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 2_000;
    private static final int DEFAULT_REQUEST_TIMEOUT_MS = 3_000;
    private static final int MAX_CONNECT_TIMEOUT_MS = 10_000;
    private static final int MAX_REQUEST_TIMEOUT_MS = 30_000;
    private static final int DEFAULT_WORKER_THREADS = 2;
    private static final int MAX_WORKER_THREADS = 4;
    private static final int DEFAULT_QUEUE_CAPACITY = 256;
    private static final int MAX_QUEUE_CAPACITY = 4_096;
    private static final int DEFAULT_SHUTDOWN_TIMEOUT_MS = 2_000;
    private static final int MAX_SHUTDOWN_TIMEOUT_MS = 10_000;

    ProviderConfiguration {
        Objects.requireNonNull(webhookUrl, "webhookUrl");
        webhookSecret = Objects.requireNonNull(webhookSecret, "webhookSecret").clone();
        Objects.requireNonNull(connectTimeout, "connectTimeout");
        Objects.requireNonNull(requestTimeout, "requestTimeout");
        Objects.requireNonNull(shutdownTimeout, "shutdownTimeout");
    }

    static ProviderConfiguration from(Function<String, String> value) {
        Objects.requireNonNull(value, "value");

        URI webhookUrl = parseWebhookUrl(required(value.apply("webhook-url"), "webhook-url"),
                parseBoolean(value.apply("allow-insecure-http"), false));
        byte[] secret = required(value.apply("webhook-secret"), "webhook-secret")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalArgumentException("webhook-secret must contain at least 32 UTF-8 bytes");
        }

        try {
            Duration connectTimeout = Duration.ofMillis(parseTimeout(
                    value.apply("connect-timeout-ms"), DEFAULT_CONNECT_TIMEOUT_MS,
                    MAX_CONNECT_TIMEOUT_MS, "connect-timeout-ms"));
            Duration requestTimeout = Duration.ofMillis(parseTimeout(
                    value.apply("request-timeout-ms"), DEFAULT_REQUEST_TIMEOUT_MS,
                    MAX_REQUEST_TIMEOUT_MS, "request-timeout-ms"));
            int workerThreads = parseBoundedInteger(
                    value.apply("worker-threads"), DEFAULT_WORKER_THREADS,
                    MAX_WORKER_THREADS, "worker-threads");
            int queueCapacity = parseBoundedInteger(
                    value.apply("queue-capacity"), DEFAULT_QUEUE_CAPACITY,
                    MAX_QUEUE_CAPACITY, "queue-capacity");
            Duration shutdownTimeout = Duration.ofMillis(parseTimeout(
                    value.apply("shutdown-timeout-ms"), DEFAULT_SHUTDOWN_TIMEOUT_MS,
                    MAX_SHUTDOWN_TIMEOUT_MS, "shutdown-timeout-ms"));

            return new ProviderConfiguration(
                    webhookUrl, secret, connectTimeout, requestTimeout,
                    workerThreads, queueCapacity, shutdownTimeout);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    @Override
    public byte[] webhookSecret() {
        return webhookSecret.clone();
    }

    private static URI parseWebhookUrl(String configured, boolean allowInsecureHttp) {
        final URI uri;
        try {
            uri = URI.create(configured);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("webhook-url must be a valid absolute URI", error);
        }

        if (!uri.isAbsolute() || uri.getHost() == null) {
            throw new IllegalArgumentException("webhook-url must be an absolute URI with a host");
        }
        if (uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("webhook-url must not contain user info or a fragment");
        }
        if (!("https".equalsIgnoreCase(uri.getScheme())
                || (allowInsecureHttp && "http".equalsIgnoreCase(uri.getScheme())))) {
            throw new IllegalArgumentException(
                    "webhook-url must use HTTPS (set allow-insecure-http=true only for trusted local networks)");
        }
        return uri;
    }

    private static boolean parseBoolean(String configured, boolean defaultValue) {
        if (configured == null || configured.isBlank()) {
            return defaultValue;
        }
        if ("true".equalsIgnoreCase(configured)) {
            return true;
        }
        if ("false".equalsIgnoreCase(configured)) {
            return false;
        }
        throw new IllegalArgumentException("allow-insecure-http must be true or false");
    }

    private static int parseTimeout(String configured, int defaultValue, int maximum, String name) {
        return parseBoundedInteger(configured, defaultValue, maximum, name);
    }

    private static int parseBoundedInteger(String configured, int defaultValue, int maximum, String name) {
        if (configured == null || configured.isBlank()) {
            return defaultValue;
        }
        final int parsed;
        try {
            parsed = Integer.parseInt(configured);
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException(name + " must be an integer", error);
        }
        if (parsed < 1 || parsed > maximum) {
            throw new IllegalArgumentException(name + " must be between 1 and " + maximum);
        }
        return parsed;
    }

    private static String required(String configured, String name) {
        if (configured == null || configured.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return configured;
    }
}
