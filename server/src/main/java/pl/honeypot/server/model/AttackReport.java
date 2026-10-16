package pl.honeypot.server.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Set;

// Body of POST /api/v1/events
public record AttackReport(
        @JsonProperty("sensor_id") String sensorId,
        @JsonProperty("state") String state,
        // Attacker MAC, null when not on the same L2 segment as the honeypot
        @JsonProperty("mac") String mac,
        // Optional, recommended: attacker IP (the server only sees the agent's IP)
        @JsonProperty("src_ip") String srcIp) {

    // Agent state machine (matches the C agent: INIT, IDLE, HANDLING_CONN, SHUTDOWN, ERROR)
    public static final Set<String> STATES = Set.of("init", "idle", "handling_conn", "shutdown", "error");
}
