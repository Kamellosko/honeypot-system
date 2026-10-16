package pl.honeypot.server.model;

import com.fasterxml.jackson.annotation.JsonProperty;

// Response to GET /api/v1/config/{sensorId}
public record AgentConfig(
        @JsonProperty("sensor_id") String sensorId,
        @JsonProperty("port_count") int portCount,
        @JsonProperty("timeout_sec") int timeoutSec,
        @JsonProperty("heartbeat_sec") int heartbeatSec,
        @JsonProperty("srv_port") int srvPort,
        // Comma separated decoy ports, e.g. "22,23,80,2222"
        @JsonProperty("ports") String ports) {
}
