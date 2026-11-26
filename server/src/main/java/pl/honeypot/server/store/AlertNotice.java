package pl.honeypot.server.store;

import java.util.List;

// One escalation: the attacker as /api/attackers shows it, why it is alarming, and its latest events
// (newest first, at most 10). Never carries passwords or raw log text.
public record AlertNotice(String agentId, ReportStore.AttackerView attacker, String reason, List<Recent> recent) {

    // One event attributed to the attacker: received_at, event.type, event.service, event.user.name, event.src.port.
    public record Recent(String at, String type, String service, String user, Integer port) {
    }
}
