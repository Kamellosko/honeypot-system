package pl.honeypot.server.api;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.NotFoundResponse;
import pl.honeypot.server.db.SensorRepository;
import pl.honeypot.server.model.AgentConfig;

// GET /api/v1/config/{sensorId} - agent asks for its configuration on startup
public final class ConfigHandler implements Handler {

    private final SensorRepository sensors;

    public ConfigHandler(SensorRepository sensors) {
        this.sensors = sensors;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        String sensorId = ctx.pathParam("sensorId");
        AgentConfig cfg = sensors.findConfig(sensorId)
                .orElseThrow(() -> new NotFoundResponse("Unknown sensor: " + sensorId));
        sensors.touch(sensorId);
        ctx.json(cfg);
    }
}
