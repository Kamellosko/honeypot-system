package pl.honeypot.server.store;

// Receives every event from an attacker whose level is worth a mail (ReportStore.ALERT_LEVELS). Called under the
// store's lock, so an implementation must return at once (buffer the event, never send mail inline).
@FunctionalInterface
public interface AlertSink {
    void activity(AlertNotice notice);
}
