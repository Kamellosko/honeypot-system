package pl.honeypot.server.store;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import pl.honeypot.server.model.AttackReport;

// Connection attempts reported by agents, appended to data/events.jsonl.
public final class EventStore {

    private final JsonlLog log;

    public EventStore(JsonlLog log) {
        this.log = log;
    }

    // Returns the generated event_id.
    public long insert(AttackReport r) {
        return log.append(r);
    }

    // Collected events, newest first. Optionally filtered by sensor and capped
    // to the most recent `limit` entries. Null arguments mean "no filter".
    public List<JsonNode> list(String sensorId, Integer limit) {
        List<JsonNode> all = log.read();
        Collections.reverse(all); // read() returns oldest first

        List<JsonNode> out = new ArrayList<>();
        for (JsonNode n : all) {
            if (sensorId != null) {
                JsonNode s = n.get("sensor_id");
                if (s == null || !sensorId.equals(s.asText())) {
                    continue;
                }
            }
            out.add(n);
            if (limit != null && out.size() >= limit) {
                break;
            }
        }
        return out;
    }
}
