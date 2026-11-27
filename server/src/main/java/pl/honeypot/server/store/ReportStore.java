package pl.honeypot.server.store;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

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
    // After this long without any activity from an IP, its next escalation is mailed again.
    private static final Duration REARM_AFTER = Duration.ofMinutes(30);
    private static final Duration ENUM_WINDOW = Duration.ofSeconds(60);
    private static final int PORT_SCAN_THRESHOLD = 3;       // distinct local ports from one IP = scan

    public record InsertResult(long eventId, boolean duplicate, boolean rejected) {
    }

    // Caps on client-chosen keys, so a stream of made-up values can't grow memory forever.
    private static final int MAX_KEYS = 200;
    private static final int MAX_AGENTS = 1000;
    // Log text can carry made-up IPs, so the attacker table is capped too; past it new IPs are not tracked.
    private static final int MAX_ATTACKERS = 10000;

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

    // One attacker (a remote IP) with running counts and sliding-window buffers. Written and read under the lock.
    private static final class AttackerState {
        String ip;
        String mac;
        String lastOperation;
        Instant firstSeen;
        Instant lastSeen;
        long connections;
        long authFailures;
        boolean scanned;   // agent reported a net.scan from this IP (not windowed)
        long events;
        final Deque<Instant> failTimes = new ArrayDeque<>();   // auth failures, pruned to FAIL_WINDOW
        final Deque<Instant> eventTimes = new ArrayDeque<>();  // any events, pruned to ENUM_WINDOW
        final Map<Integer, Instant> portTimes = new HashMap<>(); // distinct local ports, pruned to ENUM_WINDOW
        boolean confirmed;        // successful login to a decoy account
        boolean breadcrumbRead;   // read a file containing the breadcrumb marker
        boolean probed;           // service probe without a valid banner (net.probe, e.g. nmap -sV)
        long invalidUsers;        // logins to accounts that do not exist (auth.invalid_user)
        boolean decoyAttempt;     // tried to log in to a decoy account (confirmAccounts), even with a wrong password
        String alertedLevel;      // highest level already reported (mailed, or seen while replaying history); cleared after REARM_AFTER of silence
        Instant lastBruteForce;   // last time the failure window reached FAIL_THRESHOLD (stays after the window empties)
        final Deque<AlertNotice.Recent> recent = new ArrayDeque<>();   // newest first, at most RECENT_MAX
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
            @JsonProperty("by_operation") Map<String, Long> byOperation,
            @JsonProperty("by_event_type") Map<String, Long> byEventType,
            // "type/service" (e.g. "auth.failure/ssh"), or just the type when the event has no service.
            @JsonProperty("by_event_kind") Map<String, Long> byEventKind,
            @JsonProperty("unknown_event_types") long unknownEventTypes) {
    }

    // One attacker for GET /api/attackers.
    public record AttackerView(
            @JsonProperty("ip") String ip,
            @JsonProperty("mac") String mac,
            @JsonProperty("threat") String threat,         // contact|suspicious|fast_enum|brute_force|confirmed
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
            @JsonProperty("last_operation") String lastOperation,
            @JsonProperty("probed") boolean probed,
            @JsonProperty("invalid_users") long invalidUsers,
            @JsonProperty("decoy_attempt") boolean decoyAttempt,
            @JsonProperty("last_brute_force") String lastBruteForce) {
    }

    // Successful SSH login line; a login to one of confirmAccounts means the attacker used the breadcrumb password.
    private static final Pattern SSH_ACCEPTED = Pattern.compile(
            "Accepted (?:password|publickey) for (\\S+) from (\\d{1,3}(?:\\.\\d{1,3}){3})");

    // Event types the agent knows today (schema v2 catalog). Others are still stored, just counted separately.
    public static final Set<String> KNOWN_EVENT_TYPES = Set.of("file.change", "net.connection", "auth.failure",
            "auth.success", "samba.audit", "system.heartbeat", "system.source_unavailable",
            "system.observation_gap", "log.entry", "system.unknown", "auth.attempt", "net.scan",
            "auth.invalid_user", "auth.denied", "net.probe");

    // Levels worth an e-mail; lower ones (suspicious, contact) are mostly noise on a local network.
    public static final Set<String> ALERT_LEVELS = Set.of("fast_enum", "brute_force", "bait", "confirmed");
    private static final Set<String> AUTH_TYPES = Set.of("auth.failure", "auth.invalid_user", "auth.attempt");
    private static final int RECENT_MAX = 10;

    private final JsonlLog log;
    private final Object lock = new Object();
    private volatile AlertSink alertSink;
    private final Set<String> touched = new LinkedHashSet<>();   // attacker IPs changed by the current index(); under lock
    private final Set<String> confirmAccounts;
    private final String breadcrumbMarker;

    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Map<String, AgentState> agents = new ConcurrentHashMap<>();
    private final Map<String, Long> bySource = new ConcurrentHashMap<>();
    private final Map<String, Long> byClassification = new ConcurrentHashMap<>();
    private final Map<String, Long> byOperation = new ConcurrentHashMap<>();
    private final Map<String, Long> byEventType = new ConcurrentHashMap<>();
    private final Map<String, Long> byEventKind = new ConcurrentHashMap<>();
    private volatile long unknownEventTypes;
    private final Map<String, AttackerState> attackers = new ConcurrentHashMap<>();
    private volatile long totalEvents;

    public ReportStore(JsonlLog log, Set<String> confirmAccounts, String breadcrumbMarker) {
        this.log = log;
        this.confirmAccounts = confirmAccounts;
        this.breadcrumbMarker = breadcrumbMarker;
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
                index(n, false);   // history: remember levels, never mail
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
            index(stamped, true);   // liveness uses the server's received_at, not the agent's
            return new InsertResult(stamped.get("event_id").asLong(), false, false);
        }
    }

    // Sends escalations to sink from now on; null stops them. Reports already stored are never re-sent.
    public void setAlertSink(AlertSink sink) {
        this.alertSink = sink;
    }

    // Updates liveness and counters for one accepted report. Caller holds lock.
    // notify=false while replaying history: levels are remembered as reported, nothing is sent.
    private void index(JsonNode n, boolean notify) {
        touched.clear();
        totalEvents++;
        bump(bySource, text(n, "source"));
        bump(byOperation, capKey(byOperation, text(n, "operation")));
        JsonNode analysis = n.get("analysis");
        String classification = analysis != null ? text(analysis, "classification") : null;
        bump(byClassification, capKey(byClassification, classification));

        JsonNode event = n.get("event");
        String eventType = event != null ? text(event, "type") : null;
        if (eventType != null) {
            bump(byEventType, capKey(byEventType, eventType));
            String service = text(event, "service");
            String kind = service != null ? eventType + "/" + service : eventType;
            bump(byEventKind, capKey(byEventKind, kind));
            if (!KNOWN_EVENT_TYPES.contains(eventType)) {
                unknownEventTypes++;
            }
        }

        Instant parsed = parse(text(n, "received_at"));
        final Instant at = parsed != null ? parsed : Instant.now();
        String operation = text(n, "operation");

        // A port scan the agent already counted over its own window: mark the source, do not recount packets.
        if ("net.scan".equals(eventType)) {
            JsonNode src = event.get("src");
            String ip = src != null ? text(src, "ip") : null;
            if (ip != null) {
                markScanner(ip, at);
            }
        }

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
        // Probe or a guess at a non-existent account: suspicious, but not a failed password (that line comes separately).
        if ("net.probe".equals(eventType) || "auth.invalid_user".equals(eventType)) {
            JsonNode src = event.get("src");
            String ip = src != null ? text(src, "ip") : null;
            if (ip != null) {
                flagSuspect(ip, at, operation, "net.probe".equals(eventType));
            }
        }

        // Attacker from a failed login (SSH and SMB both land here as authentication_failure);
        // a Samba access denial (auth.denied) counts the same.
        // Only the first address counts: the agent puts the real client ("remote host [..]" in Samba,
        // "from IP" in sshd) first, while later ones are this server ("local host [..]") or made-up
        // addresses the attacker typed into the user name.
        if ("authentication_failure".equals(classification) || "auth.denied".equals(eventType)) {
            // v2 reports carry the parsed source address; v1 falls back to the text-derived endpoint.
            JsonNode src = event != null ? event.get("src") : null;
            String ip = src != null ? text(src, "ip") : null;
            if (ip == null) {
                ip = firstEndpoint(n);
            }
            if (ip != null) {
                recordAttacker(ip, null, at, true, null, operation);
            }
        }

        // A login attempt on a decoy account means the attacker already found the breadcrumb.
        if (eventType != null && AUTH_TYPES.contains(eventType)) {   // Set.of rejects contains(null)
            JsonNode user = event.get("user");
            String name = user != null ? text(user, "name") : null;
            JsonNode src = event.get("src");
            String ip = src != null ? text(src, "ip") : null;
            if (name != null && ip != null && confirmAccounts.contains(name)) {
                AttackerState s = attacker(ip, at);
                if (s != null) {
                    s.decoyAttempt = true;
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
                markAttacker(firstEndpoint(n), at, false, true);
            }
        }

        String agentId = text(n, "agent_id");
        remember(event, at);
        escalate(agentId, at, notify);
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

    // IP of network_context.endpoints[0], or null.
    private static String firstEndpoint(JsonNode n) {
        JsonNode nc = n.get("network_context");
        JsonNode eps = nc != null ? nc.get("endpoints") : null;
        return eps != null && eps.isArray() && eps.size() > 0 ? text(eps.get(0), "ip") : null;
    }

    // Finds or creates the state for a remote IP; null for loopback or when the table is full. Caller holds lock.
    private AttackerState attacker(String ip, Instant at) {
        if (isLoopback(ip) || (!attackers.containsKey(ip) && attackers.size() >= MAX_ATTACKERS)) {
            return null;
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
        // Silence long enough: the IP is a fresh arrival again, so its next escalation is reported anew.
        if (s.lastSeen != null && at.isAfter(s.lastSeen.plus(REARM_AFTER))) {
            s.alertedLevel = null;
        }
        touched.add(ip);
        return s;
    }

    // Adds the event to its source's recent list (only what the mail may show: no password, no raw text).
    private void remember(JsonNode event, Instant at) {
        JsonNode src = event != null ? event.get("src") : null;
        String ip = src != null ? text(src, "ip") : null;
        AttackerState s = ip != null && touched.contains(ip) ? attackers.get(ip) : null;
        if (s == null) {
            return;
        }
        JsonNode user = event.get("user");
        JsonNode port = src.get("port");
        s.recent.addFirst(new AlertNotice.Recent(iso(at), text(event, "type"), text(event, "service"),
                user != null ? text(user, "name") : null,
                port != null && port.canConvertToInt() ? port.asInt() : null));
        while (s.recent.size() > RECENT_MAX) {
            s.recent.removeLast();
        }
    }

    // Reports every touched attacker whose level rose above the one already reported. Caller holds lock.
    private void escalate(String agentId, Instant at, boolean notify) {
        for (String ip : touched) {
            AttackerState s = attackers.get(ip);
            if (s == null) {
                continue;
            }
            String level = threatOf(s, at);
            if (!ALERT_LEVELS.contains(level) || rank(level) <= rank(s.alertedLevel)) {
                continue;
            }
            s.alertedLevel = level;
            AlertSink sink = alertSink;
            if (notify && sink != null) {
                sink.escalated(new AlertNotice(agentId, view(s, at), REASONS.get(level), List.copyOf(s.recent)));
            }
        }
    }

    private static final Map<String, String> REASONS = Map.of(
            "fast_enum", "skan portów albo 3+ porty w minutę",
            "brute_force", "5+ nieudanych logowań w 10 min",
            "bait", "próba logowania na konto-przynętę albo odczyt pliku-przynęty",
            "confirmed", "udane logowanie na konto-przynętę");

    // Records one attacker observation. Caller holds lock. Loopback is skipped so
    // the agent's own upload/tunnel traffic on 127.0.0.1 is not counted.
    private void recordAttacker(String ip, String mac, Instant at, boolean authFailure, Integer localPort, String op) {
        AttackerState s = attacker(ip, at);
        if (s == null) {
            return;
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
            if (s.failTimes.size() >= FAIL_THRESHOLD && (s.lastBruteForce == null || at.isAfter(s.lastBruteForce))) {
                s.lastBruteForce = at;
            }
        } else {
            s.connections++;
            if (localPort != null) {
                s.portTimes.put(localPort, at);
                s.portTimes.values().removeIf(t -> t.isBefore(at.minus(ENUM_WINDOW)));
            }
        }
    }

    // Flags an IP the agent reported as a port scanner. Caller holds lock.
    private void markScanner(String ip, Instant at) {
        AttackerState s = attacker(ip, at);
        if (s == null) {
            return;
        }
        if (s.lastSeen == null || !at.isBefore(s.lastSeen)) {
            s.lastSeen = at;
        }
        s.scanned = true;
    }

    // Flags an IP that probed a service or tried a non-existent account. Caller holds lock.
    private void flagSuspect(String ip, Instant at, String op, boolean probe) {
        AttackerState s = attacker(ip, at);
        if (s == null) {
            return;
        }
        if (s.lastSeen == null || !at.isBefore(s.lastSeen)) {
            s.lastSeen = at;
            s.lastOperation = op;
        }
        s.events++;
        s.eventTimes.addLast(at);
        pruneOlderThan(s.eventTimes, at.minus(ENUM_WINDOW));
        if (probe) {
            s.probed = true;
        } else {
            s.invalidUsers++;
        }
    }

    // Flags an IP from content signals (confirmed login, breadcrumb read). Caller holds lock.
    private void markAttacker(String ip, Instant at, boolean confirmed, boolean breadcrumb) {
        AttackerState s = attacker(ip, at);
        if (s == null) {
            return;
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

    // All attackers seen so far, most threatening first. Takes the lock: the window buffers are not thread-safe.
    public List<AttackerView> attackers() {
        Instant now = Instant.now();
        List<AttackerView> out = new ArrayList<>();
        synchronized (lock) {
            for (AttackerState s : attackers.values()) {
                out.add(view(s, now));
            }
        }
        out.sort((x, y) -> {
            int t = rank(y.threat()) - rank(x.threat());
            return t != 0 ? t : y.lastSeen().compareTo(x.lastSeen());
        });
        return out;
    }

    // Level of one attacker at a given moment (the windows are counted back from 'now'). Caller holds lock.
    private static String threatOf(AttackerState s, Instant now) {
        int fails = countSince(s.failTimes, now.minus(FAIL_WINDOW));
        return s.confirmed ? "confirmed"
                : (s.decoyAttempt || s.breadcrumbRead) ? "bait"
                : fails >= FAIL_THRESHOLD ? "brute_force"
                : (distinctPorts(s, now) >= PORT_SCAN_THRESHOLD || s.scanned) ? "fast_enum"
                : (s.authFailures > 0 || s.probed || s.invalidUsers > 0) ? "suspicious"
                : "contact";
    }

    private static int distinctPorts(AttackerState s, Instant now) {
        Instant cut = now.minus(ENUM_WINDOW);
        return (int) s.portTimes.values().stream().filter(t -> !t.isBefore(cut)).count();
    }

    private static AttackerView view(AttackerState s, Instant now) {
        return new AttackerView(s.ip, s.mac, threatOf(s, now), iso(s.firstSeen), iso(s.lastSeen),
                s.connections, s.authFailures, s.events, countSince(s.failTimes, now.minus(FAIL_WINDOW)),
                countSince(s.eventTimes, now.minus(ENUM_WINDOW)), distinctPorts(s, now),
                s.confirmed, s.breadcrumbRead, s.lastOperation, s.probed, s.invalidUsers, s.decoyAttempt,
                iso(s.lastBruteForce));
    }

    private static int rank(String threat) {
        if (threat == null) {
            return -1;
        }
        return switch (threat) {
            case "confirmed" -> 5;
            case "bait" -> 4;
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
                new TreeMap<>(byOperation),
                new TreeMap<>(byEventType),
                new TreeMap<>(byEventKind),
                unknownEventTypes);
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
