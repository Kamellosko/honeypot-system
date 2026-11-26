package pl.honeypot.server.alert;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class AlertConfigTest {

    private static Properties props(String... kv) {
        Properties p = new Properties();
        for (int i = 0; i < kv.length; i += 2) {
            p.setProperty(kv[i], kv[i + 1]);
        }
        return p;
    }

    @Test
    void defaultsWhenDisabled() {
        AlertConfig c = AlertConfig.from(new Properties());
        assertFalse(c.enabled());
        assertEquals(25, c.port());
        assertFalse(c.starttls());
        assertEquals(60, c.maxPerHour());
    }

    @Test
    void parsesRecipientList() {
        AlertConfig c = AlertConfig.from(props("alert.enabled", "true", "alert.smtp.host", "192.168.56.1",
                "alert.from", "honeypot@x.local", "alert.to", " a@x.pl, b@y.pl "));
        assertTrue(c.enabled());
        assertEquals(List.of("a@x.pl", "b@y.pl"), c.to());
    }

    @Test
    void enabledWithoutHostFails() {
        var e = assertThrows(IllegalArgumentException.class, () -> AlertConfig.from(props(
                "alert.enabled", "true", "alert.from", "honeypot@x.local", "alert.to", "a@x.pl")));
        assertTrue(e.getMessage().contains("alert.smtp.host"));
    }

    @Test
    void enabledWithoutRecipientFails() {
        var e = assertThrows(IllegalArgumentException.class, () -> AlertConfig.from(props(
                "alert.enabled", "true", "alert.smtp.host", "h", "alert.from", "honeypot@x.local", "alert.to", " , ")));
        assertTrue(e.getMessage().contains("alert.to"));
    }
}
