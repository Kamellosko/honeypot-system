package pl.honeypot.server.api;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import pl.honeypot.server.store.ReportStore;

// GET /api/attackers - remote IPs seen in connections and failed logins, graded
// by behaviour (contact / suspicious / fast_enum / brute_force). On this host
// nobody legitimate connects, so every listed IP is hostile.
public final class AttackersHandler implements Handler {

    private final ReportStore reports;

    public AttackersHandler(ReportStore reports) {
        this.reports = reports;
    }

    @Override
    public void handle(Context ctx) {
        ctx.json(reports.attackers());
    }
}
