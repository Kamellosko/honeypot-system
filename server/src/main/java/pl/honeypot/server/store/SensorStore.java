package pl.honeypot.server.store;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import pl.honeypot.server.model.AgentConfig;

// Sensors are pre-provisioned by the admin in a JSON file loaded at startup.
// Liveness (status + last_seen) is tracked in memory; it resets to "unknown"
// on restart and is not persisted.
public final class SensorStore {

    // One sensor as declared in the provisioning file (config/sensors.json).
    public record SensorDef(
            @JsonProperty("sensor_id") String sensorId,
            @JsonProperty("hostname") String hostname,
            @JsonProperty("timeout_sec") Integer timeoutSec,
            @JsonProperty("heartbeat_sec") Integer heartbeatSec,
            @JsonProperty("srv_port") Integer srvPort,
            @JsonProperty("ports") List<Integer> ports) {
    }

    public record Liveness(String status, String lastSeen) {
    }

    private final Map<String, SensorDef> defs;
    private final Map<String, Liveness> liveness = new ConcurrentHashMap<>();

    private SensorStore(Map<String, SensorDef> defs) {
        this.defs = defs;
    }

    // Loads and validates the provisioning file. Fails fast on bad input so a
    // misconfigured deployment doesn't start silently serving nothing.
    public static SensorStore load(Path file, ObjectMapper mapper) throws IOException {
        if (!Files.exists(file)) {
            throw new IOException("Missing sensors file: " + file.toAbsolutePath());
        }
        List<SensorDef> list;
        try {
            list = mapper.readValue(Files.readAllBytes(file), new TypeReference<List<SensorDef>>() {});
        } catch (IOException e) {
            throw new IOException("Cannot parse sensors file " + file.toAbsolutePath() + ": " + e.getMessage(), e);
        }

        Map<String, SensorDef> defs = new LinkedHashMap<>();
        for (SensorDef d : list) {
            if (d.sensorId() == null || d.sensorId().isBlank()) {
                throw new IOException("sensors file has an entry without sensor_id");
            }
            if (d.ports() == null || d.ports().isEmpty()) {
                throw new IOException("sensor " + d.sensorId() + " has no ports");
            }
            if (defs.put(d.sensorId(), withDefaults(d)) != null) {
                throw new IOException("duplicate sensor_id in sensors file: " + d.sensorId());
            }
        }
        return new SensorStore(defs);
    }

    private static SensorDef withDefaults(SensorDef d) {
        return new SensorDef(
                d.sensorId(),
                d.hostname(),
                d.timeoutSec() != null ? d.timeoutSec() : 5,
                d.heartbeatSec() != null ? d.heartbeatSec() : 30,
                d.srvPort() != null ? d.srvPort() : 8000,
                d.ports());
    }

    // Builds the agent config served by GET /api/v1/config/{sensorId}.
    public Optional<AgentConfig> findConfig(String sensorId) {
        SensorDef d = defs.get(sensorId);
        if (d == null) {
            return Optional.empty();
        }
        String portList = d.ports().stream().map(String::valueOf).collect(Collectors.joining(","));
        return Optional.of(new AgentConfig(
                d.sensorId(), d.ports().size(), d.timeoutSec(), d.heartbeatSec(), d.srvPort(), portList));
    }

    public boolean exists(String sensorId) {
        return defs.containsKey(sensorId);
    }

    // Any message from the agent counts as a sign of life.
    public void touch(String sensorId) {
        String now = DateTimeFormatter.ISO_INSTANT.format(Instant.now().truncatedTo(ChronoUnit.SECONDS));
        liveness.put(sensorId, new Liveness("online", now));
    }

    public Optional<Liveness> liveness(String sensorId) {
        return Optional.ofNullable(liveness.get(sensorId));
    }
}
