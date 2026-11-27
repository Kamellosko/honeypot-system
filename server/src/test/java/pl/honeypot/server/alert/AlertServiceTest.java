package pl.honeypot.server.alert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Test;
import pl.honeypot.server.store.AlertNotice;
import pl.honeypot.server.store.ReportStore.AttackerView;

class AlertServiceTest {

    // A clock the test moves by hand.
    static final class MovableClock extends Clock {
        Instant now = Instant.parse("2026-11-26T10:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    record Sent(String subject, String body) {
    }

    private final List<Sent> sent = new ArrayList<>();
    private final Mailer fake = (subject, body) -> sent.add(new Sent(subject, body));

    private static AlertConfig cfg(int maxPerHour) {
        return new AlertConfig(true, "h", 25, false, "", "", "honeypot@x.local", List.of("a@x.pl"), maxPerHour);
    }

    private static AlertNotice notice(String threat, String ip) {
        AttackerView v = new AttackerView(ip, null, threat, "2026-11-26T09:58:00Z", "2026-11-26T10:00:00Z",
                0, 5, 5, 5, 5, 0, false, false, "append", false, 0, false);
        return new AlertNotice("fs-finanse", v, "5+ nieudanych logowań w 10 min",
                List.of(new AlertNotice.Recent("2026-11-26T10:00:00Z", "auth.failure", "smb", "administrator", 49282)));
    }

    @Test
    void subjectFormat() {
        assertEquals("[honeypot fs-finanse] BRUTE FORCE 192.168.56.4",
                AlertFormatter.subject(notice("brute_force", "192.168.56.4")));
        assertEquals("[honeypot fs-finanse] PRZYNĘTA 192.168.56.4",
                AlertFormatter.subject(notice("bait", "192.168.56.4")));
    }

    @Test
    void bodyHasReasonCountsAndRecent() {
        String body = AlertFormatter.body(notice("brute_force", "192.168.56.4"), 0);
        assertTrue(body.contains("5+ nieudanych logowań w 10 min"));
        assertTrue(body.contains("nieudane logowania"));
        assertTrue(body.contains("192.168.56.4"));
        assertTrue(body.contains("auth.failure"));
        assertTrue(body.contains("administrator"));
        assertFalse(body.contains("pominięto"));
    }

    @Test
    void hourlyLimitCountsSkipped() throws Exception {
        MovableClock clock = new MovableClock();
        AlertService s = new AlertService(cfg(2), fake, clock);
        assertTrue(s.deliver(notice("brute_force", "192.0.2.1")));
        assertTrue(s.deliver(notice("brute_force", "192.0.2.2")));
        assertFalse(s.deliver(notice("brute_force", "192.0.2.3")));
        assertEquals(2, sent.size());
        clock.now = clock.now.plus(Duration.ofMinutes(61));
        assertTrue(s.deliver(notice("brute_force", "192.0.2.4")));
        assertTrue(sent.get(2).body().contains("pominięto 1"));
        assertTrue(s.deliver(notice("brute_force", "192.0.2.5")));
        assertFalse(sent.get(3).body().contains("pominięto"));   // counter cleared after it was reported
    }

    @Test
    void offerNeverBlocksWhenQueueFull() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        Mailer stuck = (subject, body) -> release.await();
        try (AlertService s = new AlertService(cfg(60), stuck, Clock.systemUTC())) {
            s.start();
            long t0 = System.nanoTime();
            for (int i = 0; i < 150; i++) {
                s.escalated(notice("brute_force", "192.0.2." + (i % 250)));
            }
            assertTrue(System.nanoTime() - t0 < 1_000_000_000L);
            release.countDown();
        }
    }
}
