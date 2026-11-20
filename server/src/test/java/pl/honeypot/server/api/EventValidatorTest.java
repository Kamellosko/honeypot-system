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

    private static String attempt(String extra) {
        return "{\"category\":\"authentication\",\"type\":\"auth.attempt\",\"severity\":\"medium\","
                + "\"outcome\":\"failure\",\"service\":\"ssh\",\"action\":null,\"src\":null,\"dst\":null,"
                + "\"user\":null" + extra + "}";
    }

    @Test
    void acceptsCredentialAndDetailVariants() {
        assertDoesNotThrow(() -> validate(attempt(",\"credential\":{\"password\":\"x\"},\"detail\":null")));
        assertDoesNotThrow(() -> validate(attempt(",\"credential\":{\"password\":null,\"password_base64\":\"/w==\"}")));
        assertDoesNotThrow(() -> validate(attempt(",\"credential\":null,\"detail\":null")));
        assertDoesNotThrow(() -> validate(attempt(",\"credential\":{\"password\":\"\"}")));
        assertDoesNotThrow(() -> validate(attempt(",\"detail\":{\"ports\":12,\"scan\":\"syn\",\"window_seconds\":10}")));
    }

    @Test
    void rejectsBadCredential() {
        assertThrows(BadRequestResponse.class, () -> validate(attempt(",\"credential\":\"x\"")));
        assertThrows(BadRequestResponse.class, () -> validate(attempt(",\"credential\":{\"password\":5}")));
        assertThrows(BadRequestResponse.class,
                () -> validate(attempt(",\"credential\":{\"password\":\"" + "x".repeat(1025) + "\"}")));
        assertThrows(BadRequestResponse.class,
                () -> validate(attempt(",\"credential\":{\"password\":null,\"password_base64\":7}")));
    }

    @Test
    void rejectsBadDetail() {
        assertThrows(BadRequestResponse.class, () -> validate(attempt(",\"detail\":\"x\"")));
        assertThrows(BadRequestResponse.class,
                () -> validate(attempt(",\"detail\":{\"ports\":0,\"scan\":\"syn\",\"window_seconds\":10}")));
        assertThrows(BadRequestResponse.class,
                () -> validate(attempt(",\"detail\":{\"ports\":3,\"scan\":\"bad value!\",\"window_seconds\":10}")));
        assertThrows(BadRequestResponse.class,
                () -> validate(attempt(",\"detail\":{\"ports\":3,\"scan\":\"syn\",\"window_seconds\":0}")));
    }

    @Test
    void rejectsMissingEvent() {
        assertThrows(BadRequestResponse.class, () -> EventValidator.validate(null));
    }
}
