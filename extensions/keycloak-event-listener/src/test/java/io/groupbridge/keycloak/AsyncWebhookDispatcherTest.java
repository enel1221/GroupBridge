package io.groupbridge.keycloak;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class AsyncWebhookDispatcherTest {
    @Test
    void rejectsImmediatelyWhenTheBoundedQueueIsSaturatedAndUsesDaemonWorkers() throws Exception {
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean daemonWorker = new AtomicBoolean();
        WebhookDelivery blockingDelivery = hint -> {
            daemonWorker.set(Thread.currentThread().isDaemon());
            firstStarted.countDown();
            try {
                release.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return true;
        };

        try (AsyncWebhookDispatcher dispatcher = new AsyncWebhookDispatcher(
                blockingDelivery, 1, 1, Duration.ofMillis(200))) {
            assertTrue(dispatcher.submit(hint("delivery-1")));
            assertTrue(firstStarted.await(1, TimeUnit.SECONDS));
            assertTrue(dispatcher.submit(hint("delivery-2")));
            assertFalse(dispatcher.submit(hint("delivery-3")));
            assertTrue(daemonWorker.get());
            release.countDown();
        } finally {
            release.countDown();
        }
    }

    @Test
    void shutdownIsBoundedAndDropsQueuedWork() throws Exception {
        CountDownLatch firstStarted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        List<String> started = new CopyOnWriteArrayList<>();
        WebhookDelivery stubbornDelivery = hint -> {
            started.add(hint.deliveryId());
            firstStarted.countDown();
            while (release.getCount() > 0) {
                try {
                    release.await();
                } catch (InterruptedException ignored) {
                    // Deliberately emulate a broken transport that ignores interruption.
                }
            }
            return true;
        };
        AsyncWebhookDispatcher dispatcher = new AsyncWebhookDispatcher(
                stubbornDelivery, 1, 1, Duration.ofMillis(50));

        try {
            assertTrue(dispatcher.submit(hint("delivery-1")));
            assertTrue(firstStarted.await(1, TimeUnit.SECONDS));
            assertTrue(dispatcher.submit(hint("delivery-2")));

            assertTimeoutPreemptively(Duration.ofMillis(500), dispatcher::close);
            assertTrue(started.equals(List.of("delivery-1")));
            assertFalse(dispatcher.submit(hint("delivery-after-close")));
        } finally {
            release.countDown();
        }
    }

    private static WebhookHint hint(String deliveryId) {
        return new WebhookHint(deliveryId, new WebhookPayload(
                deliveryId,
                Instant.EPOCH,
                "realm-1",
                "engineering",
                "GROUP",
                "UPDATE",
                "groups/group-1",
                "group-1"));
    }
}
