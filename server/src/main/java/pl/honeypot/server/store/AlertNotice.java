package pl.honeypot.server.store;

// One event from an alarming attacker: the attacker as /api/attackers shows it, why its level is alarming, whether this
// event raised it to a level not seen before, and the event itself (null when the report has no event block, e.g. a
// breadcrumb read found in raw log text). Never carries passwords or raw log text.
public record AlertNotice(String agentId, ReportStore.AttackerView attacker, String reason, boolean newLevel, Recent event) {

    // received_at, event.type, event.service, event.user.name, event.src.port.
    public record Recent(String at, String type, String service, String user, Integer port) {
    }
}
