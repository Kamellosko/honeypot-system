package pl.honeypot.server.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.HttpStatus;
import java.util.Map;
import java.util.regex.Pattern;
import pl.honeypot.server.store.ReportStore;

// POST /events - the single entry point the C agent posts every report to
// (file changes, renames, deletes, TCP connections, log evidence, heartbeats).
//
// The agent accepts any 2xx as "delivered" and drops the queued copy, and it
// retries otherwise. So we persist first and only then answer 2xx, and we reply
// 2xx to a duplicate too (seen report_id) so retries don't pile up.
public final class ReportHandler implements Handler {

    private static final Pattern REPORT_ID = Pattern.compile("^[0-9a-f]{64}$");

    private final ReportStore reports;

    public ReportHandler(ReportStore reports) {
        this.reports = reports;
    }

    @Override
    public void handle(Context ctx) {
        JsonNode body = read(ctx);

        if (!body.isObject()) {
            throw new BadRequestResponse("body must be a JSON object");
        }
        JsonNode schema = body.get("schema_version");
        if (schema == null || !schema.isInt() || schema.asInt() != 1) {
            throw new BadRequestResponse("schema_version must be 1");
        }
        String reportId = str(body, "report_id");
        if (reportId == null || !REPORT_ID.matcher(reportId).matches()) {
            throw new BadRequestResponse("report_id must be 64 lowercase hex chars");
        }
        if (str(body, "agent_id") == null) {
            throw new BadRequestResponse("agent_id is required");
        }

        ReportStore.InsertResult r = reports.insert(body);
        if (r.duplicate()) {
            ctx.status(HttpStatus.OK).json(Map.of("report_id", reportId, "duplicate", true));
        } else {
            ctx.status(HttpStatus.CREATED).json(Map.of("event_id", r.eventId(), "report_id", reportId));
        }
    }

    private static JsonNode read(Context ctx) {
        try {
            return ctx.bodyAsClass(JsonNode.class);
        } catch (Exception e) {
            throw new BadRequestResponse("body must be valid JSON");
        }
    }

    private static String str(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && v.isTextual() && !v.asText().isBlank() ? v.asText() : null;
    }
}
