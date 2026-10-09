package pl.honeypot.server;

import io.javalin.Javalin;
import java.nio.file.Path;
import pl.honeypot.server.api.ConfigHandler;
import pl.honeypot.server.api.ErrorHandler;
import pl.honeypot.server.api.EventHandler;
import pl.honeypot.server.api.HeartbeatHandler;
import pl.honeypot.server.db.Database;
import pl.honeypot.server.db.ErrorRepository;
import pl.honeypot.server.db.EventRepository;
import pl.honeypot.server.db.HeartbeatRepository;
import pl.honeypot.server.db.SensorRepository;

public final class Main {

    public static void main(String[] args) throws Exception {
        Path configFile = Path.of(args.length > 0 ? args[0] : "config/server.properties");
        ServerConfig cfg = ServerConfig.load(configFile);

        Database db = new Database(cfg.dbPath());
        db.runScript("/db/schema.sql");
        if (cfg.seed()) {
            db.runScript("/db/seed.sql");
        }

        SensorRepository sensors = new SensorRepository(db);
        EventRepository events = new EventRepository(db);
        HeartbeatRepository heartbeats = new HeartbeatRepository(db);
        ErrorRepository errors = new ErrorRepository(db);

        Javalin app = Javalin.create(c -> c.showJavalinBanner = false);

        // Agent -> server (agent always initiates, see projekt_honeypot.md section 2)
        app.get("/api/v1/config/{sensorId}", new ConfigHandler(sensors));
        app.post("/api/v1/events", new EventHandler(sensors, events));
        app.post("/api/v1/heartbeat", new HeartbeatHandler(sensors, heartbeats));
        app.post("/api/v1/errors", new ErrorHandler(sensors, errors));

        // TODO phase 1: GET /api/v1/sensors, GET /api/v1/events
        // TODO phase 3: GET /api/v1/ioc

        app.start(cfg.bindAddress(), cfg.port());
    }
}
