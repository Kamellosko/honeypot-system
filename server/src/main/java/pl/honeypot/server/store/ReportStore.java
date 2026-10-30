package pl.honeypot.server.store;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

// Reports pushed by agents over POST /events, appended to data/events.jsonl.
//
// Every report carries an agent-generated report_id (64 hex). Transmission may
// be retried, so the same report_id can arrive more than once; we store it only
// on first sight and acknowledge later copies without appending.
//
// Liveness and aggregate counters are kept in memory, seeded from the log on
// startup. An agent is "online" while a report was received within ONLINE_AFTER.
public final class ReportStore {

    private static final Duration ONLINE_AFTER = Duration.ofSeconds(90);

    public record InsertResult(long eventId, boolean duplicate, boolean rejected) {
    }

    // Caps on client-chosen keys, so a stream of made-up values can't grow memory forever.
    private static final int MAX_KEYS = 200;
    private static final int MAX_AGENTS = 1000;

    // One agent's liveness and running totals. Written under the lock, read without it,
    // so the mutable fields are volatile.
    private static final class AgentState {
        String agentId;
        volatile Instant firstSeen;
        volatile Instant lastSeen;
        volatile String lastSource;
        volatile String lastOperation;
        volatile String lastClassification;
        volatile long totalReports;
    }

    // Snapshot of an agent for GET /api/v1/agents.
    public record AgentView(
            @JsonProperty("agent_id") String agentId,
            @JsonProperty("status") String status,
            @JsonProperty("last_seen") String lastSeen,
            @JsonProperty("first_seen") String firstSeen,
            @JsonProperty("total_reports") long totalReports,
            @JsonProperty("last_source") String lastSource,
            @JsonProperty("last_operation") String lastOperation,
            @JsonProperty("last_classification") String lastClassification) {
    }

    // Summary for GET /api/v1/stats.
    public record Stats(
            @JsonProperty("total_events") long totalEvents,
            @JsonProperty("total_agents") int totalAgents,
            @JsonProperty("online_agents") int onlineAgents,
            @JsonProperty("by_source") Map<String, Long> bySource,
            @JsonProperty("by_classification") Map<String, Long> byClassification,
            @JsonProperty("by_operation") Map<String, Long> byOperation) {
    }

    private final JsonlLog log;
    private final Object lock = new Object();

    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Map<String, AgentState> agents = new ConcurrentHashMap<>();
    private final Map<String, Long> bySource = new ConcurrentHashMap<>();
    private final Map<String, Long> byClassification = new ConcurrentHashMap<>();
    private final Map<String, Long> byOperation = new ConcurrentHashMap<>();
    private volatile long totalEvents;

    public ReportStore(JsonlLog log) {
        this.log = log;
        rebuild();
    }

    // Seeds dedup set, liveness and counters from whatever is already on disk.
    private void rebuild() {
        synchronized (lock) {
            log.forEach(n -> {
                String reportId = text(n, "report_id");
                if (reportId != null) {
                    seen.add(reportId);
                }
                index(n);
            });
        }
    }

    // Stores a report unless its report_id was seen before. Returns the new
    // event_id (duplicate=false) or marks the copy as a duplicate (no append).
    public InsertResult insert(JsonNode report) {
        String reportId = text(report, "report_id");
        synchronized (lock) {
            if (reportId != null && seen.contains(reportId)) {
                return new InsertResult(-1, true, false);
            }
            String agentId = text(report, "agent_id");
            if (agentId != null && !agents.containsKey(agentId) && agents.size() >= MAX_AGENTS) {
                return new InsertResult(-1, false, true);
            }
            // Write first: if the append fails nothing is remembered, so the
            // agent's retry is stored instead of being answered as a duplicate.
            var stamped = log.append(report);
            if (reportId != null) {
                seen.add(reportId);
            }
            index(stamped);   // liveness uses the server's received_at, not the agent's
            return new InsertResult(stamped.get("event_id").asLong(), false, false);
        }
    }

    // Updates liveness and counters for one accepted report. Caller holds lock.
    private void index(JsonNode n) {
        totalEvents++;
        bump(bySource, text(n, "source"));
        bump(byOperation, capKey(byOperation, text(n, "operation")));
        JsonNode analysis = n.get("analysis");
        String classification = analysis != null ? text(analysis, "classification") : null;
        bump(byClassification, capKey(byClassification, classification));

        String agentId = text(n, "agent_id");
        if (agentId == null) {
            return;
        }
        Instant parsed = parse(text(n, "received_at"));
        final Instant at = parsed != null ? parsed : Instant.now();
        AgentState a = agents.computeIfAbsent(agentId, k -> {
            AgentState s = new AgentState();
            s.agentId = k;
            s.firstSeen = at;
            return s;
        });
        if (a.firstSeen == null || at.isBefore(a.firstSeen)) {
            a.firstSeen = at;
        }
        if (a.lastSeen == null || !at.isBefore(a.lastSeen)) {
            a.lastSeen = at;
            a.lastSource = text(n, "source");
            a.lastOperation = text(n, "operation");
            a.lastClassification = classification;
        }
        a.totalReports++;
    }

    // Collected reports, newest first, optionally filtered and capped.
    public List<JsonNode> list(String agentId, String source, Integer limit) {
        List<JsonNode> out = new ArrayList<>();
        log.readNewestFirst(n -> {
            if (agentId != null && !agentId.equals(text(n, "agent_id"))) {
                return true;
            }
            if (source != null && !source.equals(text(n, "source"))) {
                return true;
            }
            out.add(n);
            return limit == null || out.size() < limit;
        });
        return out;
    }

    // Lock-free: reads the concurrent map and volatile fields, so it never waits on an fsync.
    public List<AgentView> agents() {
        Instant now = Instant.now();
        List<AgentView> out = new ArrayList<>();
        for (AgentState a : agents.values()) {
            Instant lastSeen = a.lastSeen;
            boolean online = lastSeen != null
                    && Duration.between(lastSeen, now).compareTo(ONLINE_AFTER) <= 0;
            out.add(new AgentView(
                    a.agentId,
                    online ? "online" : "offline",
                    iso(lastSeen),
                    iso(a.firstSeen),
                    a.totalReports,
                    a.lastSource,
                    a.lastOperation,
                    a.lastClassification));
        }
        out.sort((x, y) -> x.agentId().compareTo(y.agentId()));
        return out;
    }

    // Lock-free, like agents(). Counts may be a moment behind each other.
    public Stats stats() {
        Instant now = Instant.now();
        int online = 0;
        for (AgentState a : agents.values()) {
            Instant lastSeen = a.lastSeen;
            if (lastSeen != null && Duration.between(lastSeen, now).compareTo(ONLINE_AFTER) <= 0) {
                online++;
            }
        }
        return new Stats(
                totalEvents,
                agents.size(),
                online,
                new TreeMap<>(bySource),
                new TreeMap<>(byClassification),
                new TreeMap<>(byOperation));
    }

    // Past MAX_KEYS distinct keys, a new key is counted under "other". Caller holds lock.
    private static String capKey(Map<String, Long> counter, String key) {
        return key == null || counter.containsKey(key) || counter.size() < MAX_KEYS ? key : "other";
    }

    private static void bump(Map<String, Long> counter, String key) {
        if (key != null) {
            counter.merge(key, 1L, Long::sum);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && v.isTextual() && !v.asText().isBlank() ? v.asText() : null;
    }

    private static Instant parse(String iso) {
        if (iso == null) {
            return null;
        }
        try {
            return Instant.parse(iso);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String iso(Instant i) {
        return i != null ? i.toString() : null;
    }
}
