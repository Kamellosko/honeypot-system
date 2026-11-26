package pl.honeypot.server.alert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import pl.honeypot.server.store.AlertNotice;
import pl.honeypot.server.store.AlertSink;

// Takes escalations from ReportStore without blocking it and mails them from one background thread.
// A slow or dead mail server only fills the bounded queue; overflow and the hourly cap are counted
// and reported in the next mail that does go out.
public final class AlertService implements AlertSink, AutoCloseable {

    static final int QUEUE_SIZE = 100;
    private static final Duration[] RETRY = {Duration.ofSeconds(30), Duration.ofMinutes(2), Duration.ofMinutes(10)};

    private final AlertConfig cfg;
    private final Mailer mailer;
    private final Clock clock;
    private final BlockingQueue<AlertNotice> queue = new ArrayBlockingQueue<>(QUEUE_SIZE);
    private final AtomicLong skipped = new AtomicLong();
    private final Deque<Instant> sentTimes = new ArrayDeque<>();   // only the worker thread (or a test) touches it
    private Thread worker;

    public AlertService(AlertConfig cfg, Mailer mailer, Clock clock) {
        this.cfg = cfg;
        this.mailer = mailer;
        this.clock = clock;
    }

    @Override
    public void escalated(AlertNotice notice) {
        if (!queue.offer(notice)) {
            skipped.incrementAndGet();
        }
    }

    public synchronized void start() {
        if (worker != null) {
            return;
        }
        worker = new Thread(this::run, "alert-mailer");
        worker.setDaemon(true);
        worker.start();
    }

    private void run() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                AlertNotice n = queue.take();
                for (int attempt = 0; ; attempt++) {
                    try {
                        deliver(n);
                        break;
                    } catch (InterruptedException e) {
                        throw e;
                    } catch (Exception e) {
                        if (attempt >= RETRY.length) {
                            System.err.println("alert: mail not sent for " + n.attacker().ip() + " ("
                                    + n.attacker().threat() + "): " + e);
                            break;
                        }
                        Thread.sleep(RETRY[attempt].toMillis());
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // One attempt: false when the hourly cap is reached (counted as skipped). Mailer errors propagate for a retry.
    boolean deliver(AlertNotice n) throws Exception {
        Instant now = clock.instant();
        Instant hourAgo = now.minus(Duration.ofHours(1));
        while (!sentTimes.isEmpty() && !sentTimes.peekFirst().isAfter(hourAgo)) {
            sentTimes.removeFirst();
        }
        if (sentTimes.size() >= cfg.maxPerHour()) {
            skipped.incrementAndGet();
            return false;
        }
        long missed = skipped.get();
        mailer.send(AlertFormatter.subject(n), AlertFormatter.body(n, missed));
        skipped.addAndGet(-missed);
        sentTimes.addLast(now);
        return true;
    }

    @Override
    public synchronized void close() {
        if (worker != null) {
            worker.interrupt();
            worker = null;
        }
    }
}
