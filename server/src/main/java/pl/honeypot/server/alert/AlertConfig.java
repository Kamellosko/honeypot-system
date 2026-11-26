package pl.honeypot.server.alert;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

// The alert.* keys of collector.properties. Disabled unless alert.enabled=true; when enabled,
// a missing host, sender or recipient fails startup instead of silently sending nothing.
public record AlertConfig(boolean enabled, String host, int port, boolean starttls, String user, String password,
                          String from, List<String> to, int maxPerHour) {

    public static AlertConfig from(Properties p) {
        boolean enabled = Boolean.parseBoolean(p.getProperty("alert.enabled", "false").trim());
        String host = p.getProperty("alert.smtp.host", "").trim();
        String from = p.getProperty("alert.from", "").trim();
        List<String> to = Arrays.stream(p.getProperty("alert.to", "").split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
        AlertConfig c = new AlertConfig(enabled, host,
                Integer.parseInt(p.getProperty("alert.smtp.port", "25").trim()),
                Boolean.parseBoolean(p.getProperty("alert.smtp.starttls", "false").trim()),
                p.getProperty("alert.smtp.user", "").trim(),
                p.getProperty("alert.smtp.password", ""),
                from, to,
                Integer.parseInt(p.getProperty("alert.max_per_hour", "60").trim()));
        if (enabled) {
            require(!host.isEmpty(), "alert.smtp.host");
            require(!from.isEmpty(), "alert.from");
            require(!to.isEmpty(), "alert.to");
            require(c.maxPerHour() > 0, "alert.max_per_hour");
        }
        return c;
    }

    private static void require(boolean ok, String key) {
        if (!ok) {
            throw new IllegalArgumentException(key + " is required when alert.enabled=true");
        }
    }
}
