package pl.honeypot.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import java.nio.file.Path;
import pl.honeypot.server.api.ConfigHandler;
import pl.honeypot.server.api.ErrorHandler;
import pl.honeypot.server.api.EventHandler;
import pl.honeypot.server.api.EventsQueryHandler;
import pl.honeypot.server.api.HeartbeatHandler;
import pl.honeypot.server.api.SensorsHandler;
import pl.honeypot.server.store.ErrorStore;
import pl.honeypot.server.store.EventStore;
import pl.honeypot.server.store.HeartbeatStore;
import pl.honeypot.server.store.JsonlLog;
import pl.honeypot.server.store.SensorStore;

public final class Main {

    public static void main(String[] args) throws Exception {
        Path configFile = Path.of(args.length > 0 ? args[0] : "config/server.properties");
        ServerConfig cfg = ServerConfig.load(configFile);

        ObjectMapper mapper = new ObjectMapper();

        // Sensors are pre-provisioned in a JSON file, loaded into memory.
        SensorStore sensors = SensorStore.load(cfg.sensorsFile(), mapper);

        // Reports from agents are appended to JSON Lines files under data.dir.
        Path dataDir = cfg.dataDir();
        EventStore events = new EventStore(
                new JsonlLog(dataDir.resolve("events.jsonl"), mapper, "event_id"));
        HeartbeatStore heartbeats = new HeartbeatStore(
                new JsonlLog(dataDir.resolve("heartbeats.jsonl"), mapper, "heartbeat_id"));
        ErrorStore errors = new ErrorStore(
                new JsonlLog(dataDir.resolve("errors.jsonl"), mapper, "report_id"));

        Javalin app = Javalin.create(c -> c.showJavalinBanner = false);

        // Agent -> server (agent always initiates)
        app.get("/api/v1/config/{sensorId}", new ConfigHandler(sensors));
        app.post("/api/v1/events", new EventHandler(sensors, events));
        app.post("/api/v1/heartbeat", new HeartbeatHandler(sensors, heartbeats));
        app.post("/api/v1/errors", new ErrorHandler(sensors, errors));

        // Server -> operator (read-only views)
        app.get("/api/v1/sensors", new SensorsHandler(sensors));
        app.get("/api/v1/events", new EventsQueryHandler(events));

        // TODO phase 3: GET /api/v1/ioc

        app.start(cfg.bindAddress(), cfg.port());
    }
}
