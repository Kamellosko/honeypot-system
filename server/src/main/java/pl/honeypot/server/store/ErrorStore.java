package pl.honeypot.server.store;

import pl.honeypot.server.model.ErrorReport;

// Fault reports from agents, appended to data/errors.jsonl.
public final class ErrorStore {

    private final JsonlLog log;

    public ErrorStore(JsonlLog log) {
        this.log = log;
    }

    // Returns the generated report_id.
    public long insert(ErrorReport r) {
        return log.append(r);
    }
}
