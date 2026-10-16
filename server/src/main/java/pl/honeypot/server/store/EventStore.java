package pl.honeypot.server.store;

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
}
