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
    private static final Pattern AGENT_ID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");
    private static final Pattern OPERATION = Pattern.compile("^[a-z0-9_]{1,64}$");
    private static final java.util.Set<String> SOURCES =
            java.util.Set.of("share", "log", "network", "system", "monitor", "source");

    private final ReportStore reports;
    private final int serverPort;

    public ReportHandler(ReportStore reports, int serverPort) {
        this.reports = reports;
        this.serverPort = serverPort;
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
        String agentId = str(body, "agent_id");
        if (agentId == null || !AGENT_ID.matcher(agentId).matches()) {
            throw new BadRequestResponse("agent_id must be 1-64 chars of [A-Za-z0-9._-]");
        }
        String source = str(body, "source");
        if (source != null && !SOURCES.contains(source)) {
            throw new BadRequestResponse("unknown source");
        }
        String operation = str(body, "operation");
        if (operation != null && !OPERATION.matcher(operation).matches()) {
            throw new BadRequestResponse("invalid operation");
        }

        // Agent and server share a host: the agent sees its own upload connection
        // to our loopback listener and would report it, which uploads another
        // connection, and so on. Acknowledge (so the agent drops it) but don't store.
        if (isOwnUpload(body)) {
            ctx.status(HttpStatus.OK).json(Map.of("report_id", reportId, "ignored", true));
            return;
        }

        ReportStore.InsertResult r = reports.insert(body);
        if (r.duplicate()) {
            ctx.status(HttpStatus.OK).json(Map.of("report_id", reportId, "duplicate", true));
        } else {
            ctx.status(HttpStatus.CREATED).json(Map.of("event_id", r.eventId(), "report_id", reportId));
        }
    }

    private boolean isOwnUpload(JsonNode body) {
        if (!"tcp_connection_observed".equals(str(body, "operation"))) {
            return false;
        }
        JsonNode c = body.get("connection");
        if (c == null || !c.path("local_port").canConvertToInt() || c.path("local_port").asInt() != serverPort) {
            return false;
        }
        JsonNode peer = c.get("peer");
        return isLoopback(c.path("local_ip").asText("")) && peer != null && isLoopback(peer.path("ip").asText(""));
    }

    private static boolean isLoopback(String ip) {
        return ip.startsWith("127.") || ip.equals("::1");
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
