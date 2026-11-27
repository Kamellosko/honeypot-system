package pl.honeypot.server.alert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import pl.honeypot.server.store.AlertNotice;
import pl.honeypot.server.store.AlertSink;

// Collects events from alarming attackers and mails one digest per interval (3600 s / alert.max_per_hour, so 60 s by
// default). A quiet interval sends nothing. activity() only updates an in-memory buffer, so ReportStore never waits
// on the mail server; a failed send keeps the buffer for the next interval.
public final class AlertService implements AlertSink, AutoCloseable {

    static final int MAX_ATTACKERS = 1000;

    private final AlertConfig cfg;
    private final Mailer mailer;
    private final Clock clock;
    private final Object lock = new Object();
    private Map<String, AlertFormatter.Entry> buffer = new LinkedHashMap<>();
    private long skipped;
    private Instant windowStart;
    private ScheduledExecutorService timer;

    public AlertService(AlertConfig cfg, Mailer mailer, Clock clock) {
        this.cfg = cfg;
        this.mailer = mailer;
        this.clock = clock;
        this.windowStart = clock.instant();
    }

    Duration interval() {
        return Duration.ofSeconds((3600 + cfg.maxPerHour() - 1) / cfg.maxPerHour());
    }

    @Override
    public void activity(AlertNotice notice) {
        String ip = notice.attacker().ip();
        synchronized (lock) {
            AlertFormatter.Entry e = buffer.get(ip);
            if (e == null) {
                if (buffer.size() >= MAX_ATTACKERS) {
                    skipped++;
                    return;
                }
                e = new AlertFormatter.Entry(ip);
                buffer.put(ip, e);
            }
            e.add(notice);
        }
    }

    public synchronized void start() {
        if (timer != null) {
            return;
        }
        timer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "alert-mailer");
            t.setDaemon(true);
            return t;
        });
        long every = interval().toSeconds();
        timer.scheduleAtFixedRate(() -> {
            try {
                tick();
            } catch (RuntimeException e) {
                System.err.println("alert: " + e);   // never let one bad tick stop the timer
            }
        }, every, every, TimeUnit.SECONDS);
    }

    // Sends one digest of everything buffered since the last successful mail. true = a mail went out.
    boolean tick() {
        Map<String, AlertFormatter.Entry> batch;
        long missed;
        Instant from;
        Instant now = clock.instant();
        synchronized (lock) {
            if (buffer.isEmpty() && skipped == 0) {
                windowStart = now;
                return false;
            }
            batch = buffer;
            missed = skipped;
            from = windowStart;
            buffer = new LinkedHashMap<>();
            skipped = 0;
        }
        List<AlertFormatter.Entry> entries = new ArrayList<>(batch.values());
        try {
            mailer.send(AlertFormatter.subject(entries, from, now, clock.getZone()), AlertFormatter.body(entries, missed));
        } catch (Exception e) {
            System.err.println("alert: mail not sent (" + entries.size() + " attackers, kept for the next try): " + e);
            synchronized (lock) {
                for (AlertFormatter.Entry older : batch.values()) {
                    AlertFormatter.Entry newer = buffer.get(older.ip);
                    if (newer == null) {
                        buffer.put(older.ip, older);
                    } else {
                        newer.absorb(older);
                    }
                }
                skipped += missed;
            }
            return false;
        }
        synchronized (lock) {
            windowStart = now;
        }
        return true;
    }

    @Override
    public synchronized void close() {
        if (timer != null) {
            timer.shutdownNow();
            timer = null;
        }
    }
}
