package pl.honeypot.server.api;

import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.HttpStatus;
import io.javalin.http.NotFoundResponse;
import pl.honeypot.server.store.ErrorStore;
import pl.honeypot.server.store.SensorStore;
import pl.honeypot.server.model.AttackReport;
import pl.honeypot.server.model.ErrorReport;

// POST /api/v1/errors - agent reports a fault (second message type)
public final class ErrorHandler implements Handler {

    private final SensorStore sensors;
    private final ErrorStore errors;

    public ErrorHandler(SensorStore sensors, ErrorStore errors) {
        this.sensors = sensors;
        this.errors = errors;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        ErrorReport r = validate(ctx.bodyAsClass(ErrorReport.class));

        if (!sensors.exists(r.sensorId())) {
            throw new NotFoundResponse("Unknown sensor: " + r.sensorId());
        }
        // A fault report is still a sign of life, but an ERROR state is not "healthy"
        sensors.touch(r.sensorId());

        long id = errors.insert(r);
        ctx.status(HttpStatus.CREATED).json(java.util.Map.of("report_id", id));
    }

    private static ErrorReport validate(ErrorReport r) {
        if (r.sensorId() == null || r.sensorId().isBlank()) {
            throw new BadRequestResponse("sensor_id is required");
        }
        if (r.state() == null || !AttackReport.STATES.contains(r.state())) {
            throw new BadRequestResponse("state must be one of " + AttackReport.STATES);
        }
        if (r.errorId() == null) {
            throw new BadRequestResponse("error_id is required");
        }
        return r;
    }
}
