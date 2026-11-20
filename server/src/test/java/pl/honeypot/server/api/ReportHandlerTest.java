package pl.honeypot.server.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pl.honeypot.server.store.JsonlLog;
import pl.honeypot.server.store.ReportStore;

class ReportHandlerTest {
    private Javalin app;
    private int port;
    private int counter;

    @BeforeEach
    void start() throws Exception {
        Path dir = Files.createTempDirectory("hp-handler");
        ReportStore store = new ReportStore(new JsonlLog(dir.resolve("e.jsonl"), new ObjectMapper(), "event_id"),
                Set.of(), "");
        app = Javalin.create().post("/events", new ReportHandler(store, 8443)).start(0);
        port = app.port();
    }

    @AfterEach
    void stop() {
        app.stop();
    }

    private int post(int schema, String eventJson) throws Exception {
        String id = String.format("%064x", ++counter);
        String body = "{\"schema_version\":" + schema + ",\"report_id\":\"" + id + "\",\"agent_id\":\"a1\","
                + "\"observed_at\":\"2026-11-20T10:00:00Z\",\"source\":\"log\",\"operation\":\"append\","
                + "\"path\":\"/x\",\"analysis\":{\"classification\":\"unknown\"},\"complete\":true,\"error\":null"
                + (eventJson == null ? "" : ",\"event\":" + eventJson) + "}";
        return HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/events"))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString()).statusCode();
    }

    private static String event(String type, String severity) {
        return "{\"category\":\"system\",\"type\":\"" + type + "\",\"severity\":\"" + severity
                + "\",\"outcome\":\"unknown\",\"service\":null,\"action\":null,\"src\":null,\"dst\":null,\"user\":null}";
    }

    @Test
    void acceptsV1WithoutEvent() throws Exception {
        assertEquals(201, post(1, null));
    }

    @Test
    void acceptsV2WithEvent() throws Exception {
        assertEquals(201, post(2, event("system.heartbeat", "info")));
    }

    @Test
    void storesUnknownEventType() throws Exception {
        assertEquals(201, post(2, event("future.thing", "info")));
    }

    @Test
    void rejectsV2WithoutEvent() throws Exception {
        assertEquals(400, post(2, null));
    }

    @Test
    void rejectsV2WithBadEvent() throws Exception {
        assertEquals(400, post(2, event("system.heartbeat", "bogus")));
    }

    @Test
    void rejectsUnknownSchemaVersion() throws Exception {
        assertEquals(400, post(3, event("system.heartbeat", "info")));
    }
}
