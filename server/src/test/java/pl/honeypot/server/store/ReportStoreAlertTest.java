package pl.honeypot.server.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReportStoreAlertTest {
    private static final ObjectMapper M = new ObjectMapper();
    private static final String MARKER = "kopia_zapasowa.sh";
    private Path file;
    private ReportStore store;
    private final List<AlertNotice> notices = new ArrayList<>();
    private int counter;

    @BeforeEach
    void init() throws Exception {
        file = Files.createTempDirectory("hp-alert").resolve("e.jsonl");
        store = open();
    }

    private ReportStore open() throws Exception {
        ReportStore s = new ReportStore(new JsonlLog(file, M, "event_id"), Set.of("backup_srv"), MARKER);
        s.setAlertSink(notices::add);
        return s;
    }

    private JsonNode report(String classification, String event, String extra) throws Exception {
        String id = String.format("%064x", ++counter);
        return M.readTree("{\"schema_version\":2,\"report_id\":\"" + id + "\",\"agent_id\":\"a1\","
                + "\"observed_at\":\"2026-11-26T10:00:00Z\",\"source\":\"log\",\"operation\":\"append\","
                + "\"analysis\":{\"classification\":\"" + classification + "\"}"
                + (event == null ? "" : ",\"event\":" + event) + (extra == null ? ",\"content\":\"x\"" : extra) + "}");
    }

    private static String event(String type, String ip, String user, String credential) {
        return "{\"category\":\"authentication\",\"type\":\"" + type + "\",\"severity\":\"medium\",\"outcome\":\"failure\","
                + "\"service\":\"ssh\",\"action\":null,\"src\":{\"ip\":\"" + ip + "\",\"port\":4242,\"mac\":null},"
                + "\"dst\":null,\"user\":" + (user == null ? "null" : "{\"name\":\"" + user + "\"}")
                + ",\"credential\":" + (credential == null ? "null" : credential) + "}";
    }

    private void fail(String ip, String user) throws Exception {
        store.insert(report("authentication_failure", event("auth.failure", ip, user, null), null));
    }

    @Test
    void belowAlertLevelNoNotice() throws Exception {
        for (int i = 0; i < 4; i++) {
            fail("203.0.113.9", "root");
        }
        assertTrue(notices.isEmpty());
    }

    @Test
    void fifthFailureNotifiesWithNewLevel() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(1, notices.size());
        AlertNotice n = notices.get(0);
        assertEquals("brute_force", n.attacker().threat());
        assertEquals("203.0.113.9", n.attacker().ip());
        assertEquals("a1", n.agentId());
        assertTrue(n.newLevel());
        assertEquals("auth.failure", n.event().type());
        assertEquals("root", n.event().user());
        assertEquals(4242, n.event().port());
    }

    @Test
    void laterActivityStillNotifiesWithoutNewLevel() throws Exception {
        for (int i = 0; i < 7; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(3, notices.size());
        assertFalse(notices.get(1).newLevel());
        assertFalse(notices.get(2).newLevel());
    }

    @Test
    void suspiciousDoesNotNotify() throws Exception {
        fail("203.0.113.9", "root");
        store.insert(report("service_probe", event("net.probe", "203.0.113.9", null, null), null));
        assertEquals("suspicious", store.attackers().get(0).threat());
        assertTrue(notices.isEmpty());
    }

    @Test
    void netScanNotifiesFastEnum() throws Exception {
        store.insert(report("port_scan", event("net.scan", "198.51.100.4", null, null), null));
        assertEquals(1, notices.size());
        assertEquals("fast_enum", notices.get(0).attacker().threat());
        assertTrue(notices.get(0).newLevel());
        assertEquals("net.scan", notices.get(0).event().type());
    }

    @Test
    void decoyAccountAttemptIsBait() throws Exception {
        fail("203.0.113.9", "backup_srv");
        var a = store.attackers().get(0);
        assertEquals("bait", a.threat());
        assertTrue(a.decoyAttempt());
        assertEquals(1, notices.size());
        assertEquals("bait", notices.get(0).attacker().threat());
    }

    @Test
    void breadcrumbReadIsBaitWithoutEvent() throws Exception {
        store.insert(report("samba_audit", null,
                ",\"content\":\"smbd_audit: bob|203.0.113.9|pc|Archiwum$|open|ok|IT/" + MARKER + "\","
                        + "\"network_context\":{\"endpoints\":[{\"ip\":\"203.0.113.9\"}]}"));
        assertEquals("bait", store.attackers().get(0).threat());
        assertEquals(1, notices.size());
        assertTrue(notices.get(0).newLevel());
        assertEquals(null, notices.get(0).event());   // v1-style report: nothing to show but the level
    }

    @Test
    void escalationBruteThenConfirmedMarksNewLevelTwice() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        store.insert(report("authentication_success", null,
                ",\"content\":\"Accepted password for backup_srv from 203.0.113.9 port 1 ssh2\""));
        assertEquals(2, notices.size());
        assertEquals("confirmed", notices.get(1).attacker().threat());
        assertTrue(notices.get(1).newLevel());
    }

    @Test
    void replayedHistoryIsQuietAndNotNewAfterRestart() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        notices.clear();
        store = open();   // restart: the same file is read back
        assertTrue(notices.isEmpty());
        fail("203.0.113.9", "root");
        assertEquals(1, notices.size());   // the attack goes on, so it is mailed again
        assertFalse(notices.get(0).newLevel());
    }

    @Test
    void loopbackNeverNotifies() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("127.0.0.1", "root");
        }
        assertTrue(notices.isEmpty());
    }

    @Test
    void noticeNeverCarriesPassword() throws Exception {
        store.insert(report("authentication_attempt",
                event("auth.attempt", "203.0.113.9", "backup_srv", "{\"password\":\"Tajne123\"}"), null));
        assertEquals(1, notices.size());   // attempt on the decoy account: bait
        assertEquals("auth.attempt", notices.get(0).event().type());
        assertFalse(notices.get(0).toString().contains("Tajne123"));
    }

    @Test
    void lastBruteForceSurvivesHigherLevel() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        store.insert(report("authentication_success", null,
                ",\"content\":\"Accepted password for backup_srv from 203.0.113.9 port 1 ssh2\""));
        var a = store.attackers().get(0);
        assertEquals("confirmed", a.threat());
        assertTrue(a.lastBruteForce() != null);
    }

    @Test
    void noBruteForceMeansNoLastBruteForce() throws Exception {
        for (int i = 0; i < 4; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(null, store.attackers().get(0).lastBruteForce());
    }

    @Test
    void alertIsRearmedAfterThirtyMinutesOfSilence() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(1, notices.size());
        // Push the stored history back an hour, then restart: the same IP returns after a long silence.
        String old = Files.readString(file).replaceAll("\"received_at\":\"[^\"]+\"", "\"received_at\":\"2026-11-26T10:00:00Z\"");
        Files.writeString(file, old);
        notices.clear();
        store = open();
        assertTrue(notices.isEmpty());   // replay never mails
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(1, notices.size());
        assertEquals("brute_force", notices.get(0).attacker().threat());
    }

    @Test
    void noRearmWithoutSilence() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        notices.clear();
        store = open();
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        assertTrue(notices.isEmpty());
    }
}
