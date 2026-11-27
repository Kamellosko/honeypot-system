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
    void bruteForceSendsOneNotice() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(1, notices.size());
        assertEquals("brute_force", notices.get(0).attacker().threat());
        assertEquals("203.0.113.9", notices.get(0).attacker().ip());
        assertEquals("a1", notices.get(0).agentId());
    }

    @Test
    void sixthFailureDoesNotResend() throws Exception {
        for (int i = 0; i < 6; i++) {
            fail("203.0.113.9", "root");
        }
        assertEquals(1, notices.size());
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
    void breadcrumbReadIsBait() throws Exception {
        store.insert(report("samba_audit", null,
                ",\"content\":\"smbd_audit: bob|203.0.113.9|pc|Archiwum$|open|ok|IT/" + MARKER + "\","
                        + "\"network_context\":{\"endpoints\":[{\"ip\":\"203.0.113.9\"}]}"));
        assertEquals("bait", store.attackers().get(0).threat());
        assertEquals(1, notices.size());
    }

    @Test
    void escalationBruteThenConfirmedSendsTwo() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        store.insert(report("authentication_success", null,
                ",\"content\":\"Accepted password for backup_srv from 203.0.113.9 port 1 ssh2\""));
        assertEquals(2, notices.size());
        assertEquals("confirmed", notices.get(1).attacker().threat());
    }

    @Test
    void replayedHistoryDoesNotNotifyAndIsRemembered() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("203.0.113.9", "root");
        }
        notices.clear();
        store = open();   // restart: the same file is read back
        assertTrue(notices.isEmpty());
        fail("203.0.113.9", "root");
        assertTrue(notices.isEmpty());
    }

    @Test
    void loopbackNeverNotifies() throws Exception {
        for (int i = 0; i < 5; i++) {
            fail("127.0.0.1", "root");
        }
        assertTrue(notices.isEmpty());
    }

    @Test
    void noticeHasRecentEventsWithoutPassword() throws Exception {
        store.insert(report("authentication_attempt",
                event("auth.attempt", "203.0.113.9", "root", "{\"password\":\"Tajne123\"}"), null));
        for (int i = 0; i < 5; i++) {   // auth.attempt is not a failure: 5 failures reach brute_force
            fail("203.0.113.9", "admin" + i);
        }
        var recent = notices.get(0).recent();
        assertEquals(5, recent.size());   // auth.attempt does not touch scoring (its "Failed password" line does)
        assertEquals("admin4", recent.get(0).user());
        assertEquals("auth.failure", recent.get(0).type());
        assertEquals(4242, recent.get(0).port());
        assertFalse(recent.toString().contains("Tajne123"));
    }
}
