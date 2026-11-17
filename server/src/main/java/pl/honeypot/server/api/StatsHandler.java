package pl.honeypot.server.api;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import pl.honeypot.server.store.ReportStore;

// GET /api/v1/stats - headline counters for the dashboard.
public final class StatsHandler implements Handler {

    private final ReportStore reports;

    public StatsHandler(ReportStore reports) {
        this.reports = reports;
    }

    @Override
    public void handle(Context ctx) {
        ctx.json(reports.stats());
    }
}
