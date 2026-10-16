package pl.honeypot.server.store;

import pl.honeypot.server.model.Heartbeat;

// Periodic "I'm alive" reports from agents, appended to data/heartbeats.jsonl.
public final class HeartbeatStore {

    private final JsonlLog log;

    public HeartbeatStore(JsonlLog log) {
        this.log = log;
    }

    public void insert(Heartbeat hb) {
        log.append(hb);
    }
}
