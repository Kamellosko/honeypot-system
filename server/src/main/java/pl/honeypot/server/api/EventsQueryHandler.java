package pl.honeypot.server.api;

import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import pl.honeypot.server.store.ReportStore;

// GET /api/v1/events - collected reports, newest first.
// Optional query params: agent_id, source (share|log|network|system) and limit.
public final class EventsQueryHandler implements Handler {

    private final ReportStore reports;

    public EventsQueryHandler(ReportStore reports) {
        this.reports = reports;
    }

    @Override
    public void handle(Context ctx) {
        String agentId = blankToNull(ctx.queryParam("agent_id"));
        String source = blankToNull(ctx.queryParam("source"));

        Integer limit = null;
        String rawLimit = ctx.queryParam("limit");
        if (rawLimit != null && !rawLimit.isBlank()) {
            try {
                limit = Integer.parseInt(rawLimit.trim());
            } catch (NumberFormatException e) {
                throw new BadRequestResponse("limit must be an integer");
            }
            if (limit < 1) {
                throw new BadRequestResponse("limit must be >= 1");
            }
        }

        ctx.json(reports.list(agentId, source, limit));
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
