package pl.honeypot.server.store;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
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

    // Attacker scoring windows. On this host nobody legitimate connects, so a
    // remote IP seen here is hostile; these thresholds grade how hostile.
    private static final Duration FAIL_WINDOW = Duration.ofMinutes(10);
    private static final int FAIL_THRESHOLD = 5;            // brute force
    private static final Duration ENUM_WINDOW = Duration.ofSeconds(60);
    private static final int PORT_SCAN_THRESHOLD = 3;       // distinct local ports from one IP = scan

    public record InsertResult(long eventId, boolean duplicate) {
    }

    // One agent's liveness and running totals (mutable, updated under the lock).
    private static final class AgentState {
        String agentId;
        Instant firstSeen;
        Instant lastSeen;
        String lastSource;
        String lastOperation;
        String lastClassification;
        long totalReports;
    }

    // One attacker (a remote IP) with running counts and sliding-window buffers.
    private static final class AttackerState {
        String ip;
        String mac;
        String lastOperation;
        Instant firstSeen;
        Instant lastSeen;
        long connections;
        long authFailures;
        long events;
        final Deque<Instant> failTimes = new ArrayDeque<>();   // auth failures, pruned to FAIL_WINDOW
        final Deque<Instant> eventTimes = new ArrayDeque<>();  // any events, pruned to ENUM_WINDOW
        final Map<Integer, Instant> portTimes = new HashMap<>(); // distinct local ports, pruned to ENUM_WINDOW
        boolean confirmed;        // successful login to a decoy account
        boolean breadcrumbRead;   // read a file containing the breadcrumb marker
    }

    // Snapshot of an agent for GET /api/agents.
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

    // Summary for GET /api/stats.
    public record Stats(
            @JsonProperty("total_events") long totalEvents,
            @JsonProperty("total_agents") int totalAgents,
            @JsonProperty("online_agents") int onlineAgents,
            @JsonProperty("by_source") Map<String, Long> bySource,
            @JsonProperty("by_classification") Map<String, Long> byClassification,
            @JsonProperty("by_operation") Map<String, Long> byOperation) {
    }

    // One attacker for GET /api/attackers.
    public record AttackerView(
            @JsonProperty("ip") String ip,
            @JsonProperty("mac") String mac,
            @JsonProperty("threat") String threat,         // contact|suspicious|fast_enum|brute_force
            @JsonProperty("first_seen") String firstSeen,
            @JsonProperty("last_seen") String lastSeen,
            @JsonProperty("connections") long connections,
            @JsonProperty("auth_failures") long authFailures,
            @JsonProperty("events") long events,
            @JsonProperty("failures_10m") int failures10m,
            @JsonProperty("events_1m") int events1m,
            @JsonProperty("distinct_ports") int distinctPorts,
            @JsonProperty("confirmed") boolean confirmed,
            @JsonProperty("breadcrumb_read") boolean breadcrumbRead,
            @JsonProperty("last_operation") String lastOperation) {
    }

    private final JsonlLog log;
    private final Object lock = new Object();

    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Map<String, AgentState> agents = new ConcurrentHashMap<>();
    private final Map<String, Long> bySource = new ConcurrentHashMap<>();
    private final Map<String, Long> byClassification = new ConcurrentHashMap<>();
    private final Map<String, Long> byOperation = new ConcurrentHashMap<>();
    private final Map<String, AttackerState> attackers = new ConcurrentHashMap<>();
    private long totalEvents;

    // Successful login to one of these decoy accounts = confirmed attack (the
    // passwords are not guessable). A log line whose content contains the marker
    // flags breadcrumb_read on the reader's IP.
    private static final java.util.regex.Pattern SSH_ACCEPTED = java.util.regex.Pattern.compile(
            "Accepted (?:password|publickey) for (\\S+) from (\\d{1,3}(?:\\.\\d{1,3}){3})");
    private final Set<String> confirmAccounts;
    private final String breadcrumbMarker;

    public ReportStore(JsonlLog log, Set<String> confirmAccounts, String breadcrumbMarker) {
        this.log = log;
        this.confirmAccounts = confirmAccounts;
        this.breadcrumbMarker = breadcrumbMarker;
        rebuild();
    }

    // Seeds dedup set, liveness and counters from whatever is already on disk.
    private void rebuild() {
        synchronized (lock) {
            for (JsonNode n : log.read()) {
                String reportId = text(n, "report_id");
                if (reportId != null) {
                    seen.add(reportId);
                }
                index(n);
            }
        }
    }

    // Stores a report unless its report_id was seen before. Returns the new
    // event_id (duplicate=false) or marks the copy as a duplicate (no append).
    public InsertResult insert(JsonNode report) {
        String reportId = text(report, "report_id");
        synchronized (lock) {
            if (reportId != null && seen.contains(reportId)) {
                return new InsertResult(-1, true);
            }
            // Write first: if the append fails nothing is remembered, so the
            // agent's retry is stored instead of being answered as a duplicate.
            var stamped = log.append(report);
            if (reportId != null) {
                seen.add(reportId);
            }
            index(stamped);   // liveness uses the server's received_at, not the agent's
            return new InsertResult(stamped.get("event_id").asLong(), false);
        }
    }

    // Updates liveness and counters for one accepted report. Caller holds lock.
    private void index(JsonNode n) {
        totalEvents++;
        bump(bySource, text(n, "source"));
        bump(byOperation, text(n, "operation"));
        JsonNode analysis = n.get("analysis");
        String classification = analysis != null ? text(analysis, "classification") : null;
        bump(byClassification, classification);

        Instant parsed = parse(text(n, "received_at"));
        final Instant at = parsed != null ? parsed : Instant.now();
        String operation = text(n, "operation");

        // Attacker from an observed inbound TCP connection (peer = the remote client).
        JsonNode conn = n.get("connection");
        if (conn != null) {
            JsonNode peer = conn.get("peer");
            if (peer != null) {
                JsonNode lp = conn.get("local_port");
                Integer port = lp != null && lp.canConvertToInt() ? lp.asInt() : null;
                recordAttacker(text(peer, "ip"), text(peer, "mac"), at, false, port, operation);
            }
        }
        // Attacker from a failed login (SSH and SMB both land here as authentication_failure).
        if ("authentication_failure".equals(classification)) {
            JsonNode nc = n.get("network_context");
            JsonNode eps = nc != null ? nc.get("endpoints") : null;
            if (eps != null && eps.isArray()) {
                for (JsonNode ep : eps) {
                    recordAttacker(text(ep, "ip"), text(ep, "mac"), at, true, null, operation);
                }
            }
        }

        // Confirmed login / breadcrumb read parsed from raw log content.
        String content = text(n, "content");
        if (content != null) {
            var m = SSH_ACCEPTED.matcher(content);
            while (m.find()) {
                if (confirmAccounts.contains(m.group(1))) {
                    markAttacker(m.group(2), at, true, false);
                }
            }
            if (!breadcrumbMarker.isEmpty() && content.contains(breadcrumbMarker)) {
                JsonNode nc2 = n.get("network_context");
                JsonNode eps2 = nc2 != null ? nc2.get("endpoints") : null;
                if (eps2 != null && eps2.isArray()) {
                    for (JsonNode ep : eps2) {
                        markAttacker(text(ep, "ip"), at, false, true);
                    }
                }
            }
        }

        String agentId = text(n, "agent_id");
        if (agentId == null) {
            return;
        }
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
            a.lastOperation = operation;
            a.lastClassification = classification;
        }
        a.totalReports++;
    }

    // Records one attacker observation. Caller holds lock. Loopback is skipped so
    // the agent's own upload/tunnel traffic on 127.0.0.1 is not counted.
    private void recordAttacker(String ip, String mac, Instant at, boolean authFailure, Integer localPort, String op) {
        if (isLoopback(ip)) {
            return;
        }
        AttackerState s = attackers.computeIfAbsent(ip, k -> {
            AttackerState a = new AttackerState();
            a.ip = k;
            a.firstSeen = at;
            return a;
        });
        if (s.firstSeen == null || at.isBefore(s.firstSeen)) {
            s.firstSeen = at;
        }
        if (s.lastSeen == null || !at.isBefore(s.lastSeen)) {
            s.lastSeen = at;
            s.lastOperation = op;
        }
        if (mac != null) {
            s.mac = mac;
        }
        s.events++;
        s.eventTimes.addLast(at);
        pruneOlderThan(s.eventTimes, at.minus(ENUM_WINDOW));   // bounds the buffer to the window
        if (authFailure) {
            s.authFailures++;
            s.failTimes.addLast(at);
            pruneOlderThan(s.failTimes, at.minus(FAIL_WINDOW));
        } else {
            s.connections++;
            if (localPort != null) {
                s.portTimes.put(localPort, at);
                s.portTimes.values().removeIf(t -> t.isBefore(at.minus(ENUM_WINDOW)));
            }
        }
    }

    // Flags an IP from content signals (confirmed login, breadcrumb read). Caller holds lock.
    private void markAttacker(String ip, Instant at, boolean confirmed, boolean breadcrumb) {
        if (isLoopback(ip)) {
            return;
        }
        AttackerState s = attackers.computeIfAbsent(ip, k -> {
            AttackerState a = new AttackerState();
            a.ip = k;
            a.firstSeen = at;
            return a;
        });
        if (s.firstSeen == null || at.isBefore(s.firstSeen)) {
            s.firstSeen = at;
        }
        if (s.lastSeen == null || !at.isBefore(s.lastSeen)) {
            s.lastSeen = at;
        }
        if (confirmed) {
            s.confirmed = true;
        }
        if (breadcrumb) {
            s.breadcrumbRead = true;
        }
    }

    // All attackers seen so far, most threatening first.
    public List<AttackerView> attackers() {
        Instant now = Instant.now();
        List<AttackerView> out = new ArrayList<>();
        synchronized (lock) {
            for (AttackerState s : attackers.values()) {
                int fails = countSince(s.failTimes, now.minus(FAIL_WINDOW));
                int evs = countSince(s.eventTimes, now.minus(ENUM_WINDOW));
                Instant portCut = now.minus(ENUM_WINDOW);
                int ports = (int) s.portTimes.values().stream().filter(t -> !t.isBefore(portCut)).count();
                String threat = s.confirmed ? "confirmed"
                        : fails >= FAIL_THRESHOLD ? "brute_force"
                        : ports >= PORT_SCAN_THRESHOLD ? "fast_enum"
                        : (s.authFailures > 0 || s.breadcrumbRead) ? "suspicious" : "contact";
                out.add(new AttackerView(s.ip, s.mac, threat, iso(s.firstSeen), iso(s.lastSeen),
                        s.connections, s.authFailures, s.events, fails, evs, ports,
                        s.confirmed, s.breadcrumbRead, s.lastOperation));
            }
        }
        out.sort((x, y) -> {
            int t = rank(y.threat()) - rank(x.threat());
            return t != 0 ? t : y.lastSeen().compareTo(x.lastSeen());
        });
        return out;
    }

    private static int rank(String threat) {
        return switch (threat) {
            case "confirmed" -> 4;
            case "brute_force" -> 3;
            case "fast_enum" -> 2;
            case "suspicious" -> 1;
            default -> 0;
        };
    }

    private static int countSince(Deque<Instant> q, Instant cutoff) {
        int c = 0;
        for (Instant i : q) {
            if (!i.isBefore(cutoff)) {
                c++;
            }
        }
        return c;
    }

    private static void pruneOlderThan(Deque<Instant> q, Instant cutoff) {
        while (!q.isEmpty() && q.peekFirst().isBefore(cutoff)) {
            q.removeFirst();
        }
    }

    private static boolean isLoopback(String ip) {
        return ip == null || ip.equals("::1") || ip.startsWith("127.");
    }

    // Collected reports, newest first, optionally filtered and capped.
    public List<JsonNode> list(String agentId, String source, Integer limit) {
        List<JsonNode> all = log.read();
        Collections.reverse(all); // read() returns oldest first
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode n : all) {
            if (agentId != null && !agentId.equals(text(n, "agent_id"))) {
                continue;
            }
            if (source != null && !source.equals(text(n, "source"))) {
                continue;
            }
            out.add(n);
            if (limit != null && out.size() >= limit) {
                break;
            }
        }
        return out;
    }

    public List<AgentView> agents() {
        Instant now = Instant.now();
        List<AgentView> out = new ArrayList<>();
        synchronized (lock) {
            for (AgentState a : agents.values()) {
                boolean online = a.lastSeen != null
                        && Duration.between(a.lastSeen, now).compareTo(ONLINE_AFTER) <= 0;
                out.add(new AgentView(
                        a.agentId,
                        online ? "online" : "offline",
                        iso(a.lastSeen),
                        iso(a.firstSeen),
                        a.totalReports,
                        a.lastSource,
                        a.lastOperation,
                        a.lastClassification));
            }
        }
        out.sort((x, y) -> x.agentId().compareTo(y.agentId()));
        return out;
    }

    public Stats stats() {
        Instant now = Instant.now();
        synchronized (lock) {
            int online = 0;
            for (AgentState a : agents.values()) {
                if (a.lastSeen != null
                        && Duration.between(a.lastSeen, now).compareTo(ONLINE_AFTER) <= 0) {
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
