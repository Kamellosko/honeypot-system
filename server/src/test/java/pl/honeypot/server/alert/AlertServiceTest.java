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
import org.junit.jupiter.api.Test;
import pl.honeypot.server.store.AlertNotice;
import pl.honeypot.server.store.ReportStore.AttackerView;

class AlertServiceTest {

    // A clock the test moves by hand (UTC, so the subject shows 10:00–10:01).
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
    private final MovableClock clock = new MovableClock();

    private static AlertConfig cfg(int maxPerHour) {
        return new AlertConfig(true, "h", 25, false, "", "", "honeypot@x.local", List.of("a@x.pl"), maxPerHour);
    }

    private static AlertNotice notice(String ip, String threat, boolean newLevel, String type, String service, String user) {
        AttackerView v = new AttackerView(ip, null, threat, "2026-11-26T09:58:00Z", "2026-11-26T10:00:00Z",
                0, 41, 41, 5, 5, 0, false, false, "append", false, 0, false, null);
        return new AlertNotice("fs-finanse", v, "5+ nieudanych logowań w 10 min", newLevel,
                type == null ? null : new AlertNotice.Recent("2026-11-26T10:00:30Z", type, service, user, 49282));
    }

    private AlertService service() {
        return new AlertService(cfg(60), fake, clock);
    }

    @Test
    void quietMinuteSendsNothing() throws Exception {
        AlertService s = service();
        clock.now = clock.now.plusSeconds(60);
        assertFalse(s.tick());
        assertTrue(sent.isEmpty());
    }

    @Test
    void oneMailPerTickGroupedByIpAndType() throws Exception {
        AlertService s = service();
        s.activity(notice("192.168.56.4", "brute_force", true, "auth.failure", "smb", "administrator"));
        s.activity(notice("192.168.56.4", "brute_force", false, "auth.failure", "smb", "a.kowalska"));
        s.activity(notice("192.168.56.4", "brute_force", false, "auth.failure", "smb", "administrator"));
        s.activity(notice("198.51.100.7", "fast_enum", true, "net.scan", null, null));
        clock.now = clock.now.plusSeconds(60);
        assertTrue(s.tick());
        assertEquals(1, sent.size());
        Sent m = sent.get(0);
        assertEquals("[honeypot fs-finanse] 2 atakujących, 4 zdarzenia (10:00–10:01)", m.subject());
        assertTrue(m.body().contains("192.168.56.4"), m.body());
        assertTrue(m.body().contains("BRUTE FORCE"), m.body());
        assertTrue(m.body().contains("3× SMB · nieudane logowanie"), m.body());
        assertTrue(m.body().contains("konta: administrator, a.kowalska"), m.body());
        assertTrue(m.body().contains("1× skan portów"), m.body());
        assertTrue(m.body().indexOf("192.168.56.4") < m.body().indexOf("198.51.100.7"), "worse level first");
    }

    @Test
    void newLevelIsMarkedOnlyWhenItHappened() throws Exception {
        AlertService s = service();
        s.activity(notice("192.168.56.4", "brute_force", true, "auth.failure", "smb", "x"));
        s.tick();
        s.activity(notice("192.168.56.4", "brute_force", false, "auth.failure", "smb", "x"));
        s.tick();
        assertTrue(sent.get(0).body().contains("NOWY POZIOM"));
        assertFalse(sent.get(1).body().contains("NOWY POZIOM"));
    }

    @Test
    void secondTickCarriesOnlyNewEvents() throws Exception {
        AlertService s = service();
        s.activity(notice("192.168.56.4", "brute_force", true, "auth.failure", "ssh", "root"));
        s.tick();
        s.activity(notice("192.168.56.9", "fast_enum", true, "net.scan", null, null));
        s.tick();
        assertEquals(2, sent.size());
        assertFalse(sent.get(1).body().contains("192.168.56.4"));
        assertTrue(sent.get(1).subject().contains("1 atakujący, 1 zdarzenie"), sent.get(1).subject());
    }

    @Test
    void failedSendKeepsEventsForNextTick() throws Exception {
        List<Sent> ok = new ArrayList<>();
        boolean[] down = {true};
        AlertService s = new AlertService(cfg(60), (subject, body) -> {
            if (down[0]) {
                throw new IllegalStateException("Connection refused");
            }
            ok.add(new Sent(subject, body));
        }, clock);
        s.activity(notice("192.168.56.4", "brute_force", true, "auth.failure", "ssh", "root"));
        assertFalse(s.tick());
        down[0] = false;
        s.activity(notice("192.168.56.4", "brute_force", false, "auth.failure", "ssh", "root"));
        assertTrue(s.tick());
        assertTrue(ok.get(0).body().contains("2× SSH · nieudane logowanie"), ok.get(0).body());
        assertTrue(ok.get(0).body().contains("NOWY POZIOM"));
    }

    @Test
    void eventWithoutDetailStillListsTheAttacker() throws Exception {
        AlertService s = service();
        s.activity(notice("192.168.56.4", "bait", true, null, null, null));
        assertTrue(s.tick());
        assertTrue(sent.get(0).body().contains("PRZYNĘTA"));
        assertTrue(sent.get(0).subject().contains("1 atakujący, 1 zdarzenie"));
    }

    @Test
    void intervalFollowsHourlyLimit() {
        assertEquals(Duration.ofSeconds(60), new AlertService(cfg(60), fake, clock).interval());
        assertEquals(Duration.ofSeconds(120), new AlertService(cfg(30), fake, clock).interval());
    }

    @Test
    void activityIsCheapUnderLoad() {
        AlertService s = service();
        long t0 = System.nanoTime();
        for (int i = 0; i < 20_000; i++) {
            s.activity(notice("192.0.2." + (i % 250), "brute_force", false, "auth.failure", "ssh", "u" + (i % 50)));
        }
        assertTrue(System.nanoTime() - t0 < 2_000_000_000L);
    }
}
