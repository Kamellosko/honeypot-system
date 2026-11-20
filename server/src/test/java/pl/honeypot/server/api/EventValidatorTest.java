package pl.honeypot.server.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.http.BadRequestResponse;
import org.junit.jupiter.api.Test;

class EventValidatorTest {
    private static final ObjectMapper M = new ObjectMapper();

    private static void validate(String json) throws Exception {
        EventValidator.validate(M.readTree(json));
    }

    private static String event(String src, String user, String severity) {
        return "{\"category\":\"authentication\",\"type\":\"auth.failure\",\"severity\":\"" + severity
                + "\",\"outcome\":\"failure\",\"service\":\"ssh\",\"action\":null,\"src\":" + src
                + ",\"dst\":null,\"user\":" + user + "}";
    }

    @Test
    void acceptsValidEvent() {
        assertDoesNotThrow(() -> validate(event("{\"ip\":\"203.0.113.9\",\"port\":4242,\"mac\":null}",
                "{\"name\":\"bob\"}", "medium")));
    }

    @Test
    void acceptsNullFields() {
        assertDoesNotThrow(() -> validate(event("null", "null", "info")));
    }

    @Test
    void acceptsIpv6Source() {
        assertDoesNotThrow(() -> validate(event("{\"ip\":\"2001:db8::1\",\"port\":22,\"mac\":null}", "null", "medium")));
    }

    @Test
    void rejectsUnknownSeverity() {
        assertThrows(BadRequestResponse.class, () -> validate(event("null", "null", "bogus")));
    }

    @Test
    void rejectsBadIp() {
        assertThrows(BadRequestResponse.class,
                () -> validate(event("{\"ip\":\"999.1.1.1\",\"port\":1,\"mac\":null}", "null", "low")));
    }

    @Test
    void rejectsPortZero() {
        assertThrows(BadRequestResponse.class,
                () -> validate(event("{\"ip\":\"203.0.113.9\",\"port\":0,\"mac\":null}", "null", "low")));
    }

    @Test
    void rejectsOverlongUserName() {
        String name = "x".repeat(300);
        assertThrows(BadRequestResponse.class, () -> validate(event("null", "{\"name\":\"" + name + "\"}", "low")));
    }

    @Test
    void rejectsMissingEvent() {
        assertThrows(BadRequestResponse.class, () -> EventValidator.validate(null));
    }
}
