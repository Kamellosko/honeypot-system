package pl.honeypot.server.alert;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import pl.honeypot.server.store.AlertNotice;
import pl.honeypot.server.store.ReportStore.AttackerView;

// Subject and plain-text body of the per-minute digest. Built only from AlertNotice, which holds no passwords or raw log text.
public final class AlertFormatter {

    private static final Map<String, String> LABELS = Map.of(
            "confirmed", "POTWIERDZONY",
            "bait", "PRZYNĘTA",
            "brute_force", "BRUTE FORCE",
            "fast_enum", "SKANER");
    private static final Map<String, Integer> RANK = Map.of("confirmed", 4, "bait", 3, "brute_force", 2, "fast_enum", 1);
    private static final Map<String, String> EVENTS = Map.ofEntries(
            Map.entry("auth.failure", "nieudane logowanie"),
            Map.entry("auth.attempt", "próba hasła"),
            Map.entry("auth.success", "udane logowanie"),
            Map.entry("auth.invalid_user", "nieistniejące konto"),
            Map.entry("auth.denied", "odmowa dostępu"),
            Map.entry("net.scan", "skan portów"),
            Map.entry("net.probe", "sonda usługi"),
            Map.entry("net.connection", "połączenie TCP"),
            Map.entry("file.change", "zmiana pliku"),
            Map.entry("samba.audit", "audyt Samby"));
    private static final int USERS_SHOWN = 5;
    private static final DateTimeFormatter HM = DateTimeFormatter.ofPattern("HH:mm");

    // Everything one attacker did since the last mail. Mutated only under AlertService's lock.
    static final class Entry {
        final String ip;
        String agentId;
        AttackerView latest;
        String reason;
        boolean newLevel;
        int events;
        final Map<String, Integer> counts = new LinkedHashMap<>();       // "SMB · nieudane logowanie" -> n
        final Map<String, Set<String>> users = new LinkedHashMap<>();    // same key -> account names (first USERS_SHOWN)

        Entry(String ip) {
            this.ip = ip;
        }

        void add(AlertNotice n) {
            agentId = n.agentId();
            latest = n.attacker();
            reason = n.reason();
            newLevel |= n.newLevel();
            events++;
            AlertNotice.Recent e = n.event();
            if (e != null && e.type() != null) {
                String key = label(e.type(), e.service());
                counts.merge(key, 1, Integer::sum);
                if (e.user() != null) {
                    Set<String> u = users.computeIfAbsent(key, k -> new LinkedHashSet<>());
                    if (u.size() < USERS_SHOWN) {
                        u.add(e.user());
                    }
                }
            }
        }

        // Folds an older, unsent entry into this one; this one's attacker view is the newer.
        void absorb(Entry older) {
            newLevel |= older.newLevel;
            events += older.events;
            older.counts.forEach((k, v) -> counts.merge(k, v, Integer::sum));
            older.users.forEach((k, v) -> {
                Set<String> u = users.computeIfAbsent(k, x -> new LinkedHashSet<>());
                for (String name : v) {
                    if (u.size() < USERS_SHOWN) {
                        u.add(name);
                    }
                }
            });
        }
    }

    private AlertFormatter() {
    }

    static String label(String type, String service) {
        String name = EVENTS.getOrDefault(type, type);
        return service != null ? service.toUpperCase() + " · " + name : name;
    }

    static List<Entry> ordered(List<Entry> entries) {
        return entries.stream()
                .sorted(Comparator.comparing((Entry e) -> -RANK.getOrDefault(e.latest.threat(), 0)).thenComparing(e -> e.ip))
                .toList();
    }

    static String subject(List<Entry> entries, Instant from, Instant to, ZoneId zone) {
        int events = entries.stream().mapToInt(e -> e.events).sum();
        String agent = entries.isEmpty() || entries.get(0).agentId == null ? "?" : entries.get(0).agentId;
        return "[honeypot " + agent + "] " + entries.size() + " " + attackers(entries.size()) + ", "
                + events + " " + eventsWord(events) + " (" + HM.format(from.atZone(zone)) + "–" + HM.format(to.atZone(zone)) + ")";
    }

    static String body(List<Entry> entries, long skipped) {
        StringBuilder b = new StringBuilder();
        for (Entry e : ordered(entries)) {
            AttackerView a = e.latest;
            b.append(a.ip()).append("   ").append(LABELS.getOrDefault(a.threat(), a.threat()));
            if (e.newLevel) {
                b.append("  (NOWY POZIOM)");
            }
            b.append('\n');
            b.append("  powód: ").append(e.reason).append('\n');
            if (e.counts.isEmpty()) {
                b.append("  ").append(e.events).append("× zdarzenie bez szczegółów (np. odczyt pliku-przynęty)\n");
            }
            e.counts.forEach((k, n) -> {
                b.append("  ").append(n).append("× ").append(k);
                Set<String> u = e.users.get(k);
                if (u != null && !u.isEmpty()) {
                    b.append("   konta: ").append(String.join(", ", u));
                }
                b.append('\n');
            });
            b.append("  łącznie: ").append(a.authFailures()).append(" nieudanych logowań (w ostatnich 10 min: ")
                    .append(a.failures10m()).append("), porty w ostatniej minucie: ").append(a.distinctPorts());
            if (a.decoyAttempt()) {
                b.append(", próba na konto-przynętę");
            }
            if (a.breadcrumbRead()) {
                b.append(", odczyt pliku-przynęty");
            }
            b.append("\n  pierwszy raz: ").append(a.firstSeen()).append(", ostatnio: ").append(a.lastSeen()).append("\n\n");
        }
        if (skipped > 0) {
            b.append("Uwaga: pominięto ").append(skipped).append(" zdarzeń (bufor alarmów pełny).\n\n");
        }
        b.append("Dashboard: ssh -L 8443:127.0.0.1:8443 <admin>@<wabik>  ->  https://127.0.0.1:8443/\n");
        return b.toString();
    }

    private static String attackers(int n) {
        return n == 1 ? "atakujący" : "atakujących";
    }

    private static String eventsWord(int n) {
        if (n == 1) {
            return "zdarzenie";
        }
        int tens = n % 100;
        int ones = n % 10;
        return ones >= 2 && ones <= 4 && (tens < 12 || tens > 14) ? "zdarzenia" : "zdarzeń";
    }
}
