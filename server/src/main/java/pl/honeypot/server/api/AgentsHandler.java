package pl.honeypot.server.api;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import pl.honeypot.server.store.ReportStore;

// GET /api/v1/agents - every agent seen so far with its liveness and totals.
// Agents are discovered dynamically from incoming reports (no provisioning).
public final class AgentsHandler implements Handler {

    private final ReportStore reports;

    public AgentsHandler(ReportStore reports) {
        this.reports = reports;
    }

    @Override
    public void handle(Context ctx) {
        ctx.json(reports.agents());
    }
}
