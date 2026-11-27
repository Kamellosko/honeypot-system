package pl.honeypot.server.store;

// Receives an attacker that just reached a higher alert level. Called under the store's lock,
// so an implementation must return at once (queue the work, never send mail inline).
@FunctionalInterface
public interface AlertSink {
    void escalated(AlertNotice notice);
}
