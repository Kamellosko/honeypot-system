package pl.honeypot.server.api;

import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.HttpStatus;
import io.javalin.http.NotFoundResponse;
import pl.honeypot.server.store.HeartbeatStore;
import pl.honeypot.server.store.SensorStore;
import pl.honeypot.server.model.Heartbeat;

// POST /api/v1/heartbeat - periodic "I'm alive" from the agent
public final class HeartbeatHandler implements Handler {

    private final SensorStore sensors;
    private final HeartbeatStore heartbeats;

    public HeartbeatHandler(SensorStore sensors, HeartbeatStore heartbeats) {
        this.sensors = sensors;
        this.heartbeats = heartbeats;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        Heartbeat hb = validate(ctx.bodyAsClass(Heartbeat.class));

        if (!sensors.exists(hb.sensorId())) {
            throw new NotFoundResponse("Unknown sensor: " + hb.sensorId());
        }
        sensors.touch(hb.sensorId());
        heartbeats.insert(hb);
        ctx.status(HttpStatus.NO_CONTENT);
    }

    private static Heartbeat validate(Heartbeat hb) {
        if (hb.sensorId() == null || hb.sensorId().isBlank()) {
            throw new BadRequestResponse("sensor_id is required");
        }
        if (hb.eventsSinceLast() == null || hb.eventsSinceLast() < 0) {
            throw new BadRequestResponse("events_since_last must be >= 0");
        }
        if (hb.uptimeSec() == null || hb.uptimeSec() < 0) {
            throw new BadRequestResponse("uptime_sec must be >= 0");
        }
        return hb;
    }
}
