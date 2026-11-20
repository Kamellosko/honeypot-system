package pl.honeypot.server.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReportStoreEventTest {
    private static final ObjectMapper M = new ObjectMapper();
    private ReportStore store;
    private int counter;

    @BeforeEach
    void init() throws Exception {
        store = new ReportStore(new JsonlLog(Files.createTempDirectory("hp-store").resolve("e.jsonl"), M, "event_id"),
                Set.of(), "");
    }

    private JsonNode report(int schema, String classification, String networkContext, String event) throws Exception {
        String id = String.format("%064x", ++counter);
        return M.readTree("{\"schema_version\":" + schema + ",\"report_id\":\"" + id + "\",\"agent_id\":\"a1\","
                + "\"observed_at\":\"2026-11-20T10:00:00Z\",\"source\":\"log\",\"operation\":\"append\","
                + "\"analysis\":{\"classification\":\"" + classification + "\"},\"content\":\"x\""
                + (networkContext == null ? "" : ",\"network_context\":" + networkContext)
                + (event == null ? "" : ",\"event\":" + event) + "}");
    }

    private static String authEvent(String srcIp) {
        return "{\"category\":\"authentication\",\"type\":\"auth.failure\",\"severity\":\"medium\",\"outcome\":\"failure\","
                + "\"service\":\"ssh\",\"action\":null,\"src\":{\"ip\":\"" + srcIp + "\",\"port\":1,\"mac\":null},"
                + "\"dst\":null,\"user\":{\"name\":\"bob\"}}";
    }

    @Test
    void v1FailureStillCountsAttackerFromNetworkContext() throws Exception {
        store.insert(report(1, "authentication_failure", "{\"endpoints\":[{\"ip\":\"203.0.113.9\"}]}", null));
        assertEquals("203.0.113.9", store.attackers().get(0).ip());
        assertEquals(1, store.attackers().get(0).authFailures());
    }

    @Test
    void v2FailureUsesEventSourceIp() throws Exception {
        store.insert(report(2, "authentication_failure", null, authEvent("203.0.113.77")));
        assertEquals("203.0.113.77", store.attackers().get(0).ip());
    }

    @Test
    void v2FailureWithIpv6Source() throws Exception {
        store.insert(report(2, "authentication_failure", null, authEvent("2001:db8::1")));
        assertEquals("2001:db8::1", store.attackers().get(0).ip());
    }

    @Test
    void unknownEventTypeIsCounted() throws Exception {
        String ev = "{\"category\":\"x\",\"type\":\"future.thing\",\"severity\":\"info\",\"outcome\":\"unknown\","
                + "\"service\":null,\"action\":null,\"src\":null,\"dst\":null,\"user\":null}";
        store.insert(report(2, "unknown", null, ev));
        assertEquals(1L, store.stats().unknownEventTypes());
        assertEquals(1L, store.stats().byEventType().get("future.thing"));
    }

    private static String typedEvent(String type, String srcIp) {
        return "{\"category\":\"x\",\"type\":\"" + type + "\",\"severity\":\"medium\",\"outcome\":\"unknown\","
                + "\"service\":null,\"action\":null,\"src\":{\"ip\":\"" + srcIp + "\",\"port\":null,\"mac\":null},"
                + "\"dst\":null,\"user\":null}";
    }

    @Test
    void netScanIsKnownAndMarksScannerAsFastEnum() throws Exception {
        store.insert(report(2, "port_scan", null, typedEvent("net.scan", "192.0.2.50")));
        assertEquals(1L, store.stats().byEventType().get("net.scan"));
        assertEquals(0L, store.stats().unknownEventTypes());
        assertEquals("192.0.2.50", store.attackers().get(0).ip());
        assertEquals("fast_enum", store.attackers().get(0).threat());
    }

    @Test
    void authAttemptIsKnownAndDoesNotDoubleCountFailures() throws Exception {
        store.insert(report(2, "authentication_attempt", null, typedEvent("auth.attempt", "203.0.113.9")));
        assertEquals(0L, store.stats().unknownEventTypes());
        assertTrue(store.attackers().isEmpty());
        store.insert(report(2, "authentication_failure", null, authEvent("203.0.113.9")));
        store.insert(report(2, "authentication_attempt", null, typedEvent("auth.attempt", "203.0.113.9")));
        assertEquals(1, store.attackers().get(0).authFailures());
    }

    @Test
    void byEventTypeCountsKnownType() throws Exception {
        store.insert(report(2, "authentication_failure", null, authEvent("203.0.113.9")));
        assertEquals(1L, store.stats().byEventType().get("auth.failure"));
        assertTrue(store.stats().unknownEventTypes() == 0);
    }
}
