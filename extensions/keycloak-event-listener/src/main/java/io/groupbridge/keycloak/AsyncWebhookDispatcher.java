package io.groupbridge.keycloak;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

final class AsyncWebhookDispatcher implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(AsyncWebhookDispatcher.class.getName());

    private final WebhookDelivery delivery;
    private final ThreadPoolExecutor executor;
    private final Duration shutdownTimeout;

    AsyncWebhookDispatcher(WebhookDelivery delivery, ProviderConfiguration configuration) {
        this(delivery, configuration.workerThreads(), configuration.queueCapacity(),
                configuration.shutdownTimeout());
    }

    AsyncWebhookDispatcher(
            WebhookDelivery delivery,
            int workerThreads,
            int queueCapacity,
            Duration shutdownTimeout) {
        this(delivery, workerThreads, queueCapacity, shutdownTimeout, daemonThreadFactory());
    }

    AsyncWebhookDispatcher(
            WebhookDelivery delivery,
            int workerThreads,
            int queueCapacity,
            Duration shutdownTimeout,
            ThreadFactory threadFactory) {
        this.delivery = delivery;
        this.shutdownTimeout = shutdownTimeout;
        this.executor = new ThreadPoolExecutor(
                workerThreads,
                workerThreads,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                threadFactory,
                new ThreadPoolExecutor.AbortPolicy());
    }

    boolean submit(WebhookHint hint) {
        try {
            executor.execute(new DeliveryTask(hint));
            return true;
        } catch (RejectedExecutionException rejected) {
            logDropped(hint);
            return false;
        }
    }

    @Override
    public void close() {
        executor.shutdown();
        boolean terminated = awaitTermination(shutdownTimeout);
        if (!terminated) {
            List<Runnable> queued = executor.shutdownNow();
            for (Runnable runnable : queued) {
                if (runnable instanceof DeliveryTask task) {
                    logDropped(task.hint);
                }
            }
        }
        delivery.close();
    }

    private boolean awaitTermination(Duration timeout) {
        try {
            return executor.awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static ThreadFactory daemonThreadFactory() {
        AtomicInteger sequence = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable,
                    "groupbridge-webhook-" + sequence.incrementAndGet());
            thread.setDaemon(true);
            thread.setUncaughtExceptionHandler((failedThread, error) ->
                    LOGGER.log(System.Logger.Level.ERROR,
                            "GroupBridge webhook worker failed: cause={0}",
                            error.getClass().getSimpleName()));
            return thread;
        };
    }

    private static void logDropped(WebhookHint hint) {
        LOGGER.log(System.Logger.Level.WARNING,
                "GroupBridge webhook dropped: delivery={0}", hint.deliveryId());
    }

    private final class DeliveryTask implements Runnable {
        private final WebhookHint hint;

        private DeliveryTask(WebhookHint hint) {
            this.hint = hint;
        }

        @Override
        public void run() {
            delivery.deliver(hint);
        }
    }
}
