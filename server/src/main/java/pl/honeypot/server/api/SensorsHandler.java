package pl.honeypot.server.api;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import pl.honeypot.server.store.SensorStore;

// GET /api/v1/sensors - all provisioned sensors with their liveness
public final class SensorsHandler implements Handler {

    private final SensorStore sensors;

    public SensorsHandler(SensorStore sensors) {
        this.sensors = sensors;
    }

    @Override
    public void handle(Context ctx) {
        ctx.json(sensors.list());
    }
}
