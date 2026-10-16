package pl.honeypot.server.model;

import com.fasterxml.jackson.annotation.JsonProperty;

// Body of POST /api/v1/heartbeat (boxed fields to detect missing values)
public record Heartbeat(
        @JsonProperty("sensor_id") String sensorId,
        @JsonProperty("events_since_last") Integer eventsSinceLast,
        @JsonProperty("uptime_sec") Long uptimeSec) {
}
