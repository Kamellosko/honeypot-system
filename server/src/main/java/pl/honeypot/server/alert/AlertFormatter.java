package pl.honeypot.server.alert;

import java.util.Map;
import pl.honeypot.server.store.AlertNotice;
import pl.honeypot.server.store.ReportStore.AttackerView;

// Subject and plain-text body of an alert mail. Built only from AlertNotice, which holds no passwords or raw log text.
public final class AlertFormatter {

    private static final Map<String, String> LABELS = Map.of(
            "confirmed", "POTWIERDZONY",
            "bait", "PRZYNĘTA",
            "brute_force", "BRUTE FORCE",
            "fast_enum", "SKANER");

    private AlertFormatter() {
    }

    public static String subject(AlertNotice n) {
        AttackerView a = n.attacker();
        return "[honeypot " + (n.agentId() != null ? n.agentId() : "?") + "] "
                + LABELS.getOrDefault(a.threat(), a.threat()) + " " + a.ip();
    }

    public static String body(AlertNotice n, long skipped) {
        AttackerView a = n.attacker();
        StringBuilder b = new StringBuilder();
        b.append("Adres:     ").append(a.ip()).append(a.mac() != null ? " (MAC " + a.mac() + ")" : "").append('\n');
        b.append("Ocena:     ").append(LABELS.getOrDefault(a.threat(), a.threat())).append('\n');
        b.append("Powód:     ").append(n.reason()).append('\n');
        b.append("Czujnik:   ").append(n.agentId()).append('\n');
        b.append("Pierwszy:  ").append(a.firstSeen()).append('\n');
        b.append("Ostatnio:  ").append(a.lastSeen()).append("\n\n");
        b.append("nieudane logowania: ").append(a.authFailures())
                .append(" (w ostatnich 10 min: ").append(a.failures10m()).append(")\n");
        b.append("porty w ostatniej minucie: ").append(a.distinctPorts()).append('\n');
        if (a.probed()) {
            b.append("sonda usługi (połączenie bez logowania): tak\n");
        }
        if (a.invalidUsers() > 0) {
            b.append("próby na nieistniejące konta: ").append(a.invalidUsers()).append('\n');
        }
        if (a.decoyAttempt()) {
            b.append("próba logowania na konto-przynętę: tak\n");
        }
        if (a.breadcrumbRead()) {
            b.append("odczyt pliku-przynęty: tak\n");
        }
        if (!n.recent().isEmpty()) {
            b.append("\nOstatnie zdarzenia (najnowsze pierwsze):\n");
            for (AlertNotice.Recent r : n.recent()) {
                b.append("  ").append(r.at()).append("  ").append(r.type());
                if (r.service() != null) {
                    b.append(" / ").append(r.service());
                }
                if (r.user() != null) {
                    b.append("  konto: ").append(r.user());
                }
                if (r.port() != null) {
                    b.append("  port źródłowy: ").append(r.port());
                }
                b.append('\n');
            }
        }
        if (skipped > 0) {
            b.append("\nUwaga: pominięto ").append(skipped)
                    .append(" alarmów (limit na godzinę albo pełna kolejka).\n");
        }
        b.append("\nDashboard: ssh -L 8443:127.0.0.1:8443 <admin>@<wabik>  ->  https://127.0.0.1:8443/\n");
        return b.toString();
    }
}
