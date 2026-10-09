package pl.honeypot.server.model;

import com.fasterxml.jackson.annotation.JsonProperty;

// Body of POST /api/v1/errors - agent reports a fault (second message type)
public record ErrorReport(
        @JsonProperty("sensor_id") String sensorId,
        @JsonProperty("state") String state,
        // Agent-defined error code, see docs/api.md
        @JsonProperty("error_id") Integer errorId) {
}
