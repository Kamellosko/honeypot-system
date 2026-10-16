package pl.honeypot.server.api;

import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.HttpStatus;
import io.javalin.http.NotFoundResponse;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import pl.honeypot.server.store.EventStore;
import pl.honeypot.server.store.SensorStore;
import pl.honeypot.server.model.AttackReport;

// POST /api/v1/events - agent reports a connection attempt on a decoy port
public final class EventHandler implements Handler {

    private static final Pattern MAC = Pattern.compile("^([0-9a-f]{2}:){5}[0-9a-f]{2}$");

    private final SensorStore sensors;
    private final EventStore events;

    public EventHandler(SensorStore sensors, EventStore events) {
        this.sensors = sensors;
        this.events = events;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        AttackReport r = validate(ctx.bodyAsClass(AttackReport.class));

        if (!sensors.exists(r.sensorId())) {
            throw new NotFoundResponse("Unknown sensor: " + r.sensorId());
        }
        sensors.touch(r.sensorId());

        long id = events.insert(r);
        ctx.status(HttpStatus.CREATED).json(Map.of("event_id", id));
    }

    // Rejects malformed input and normalizes the MAC to lower case
    private static AttackReport validate(AttackReport r) {
        if (r.sensorId() == null || r.sensorId().isBlank()) {
            throw new BadRequestResponse("sensor_id is required");
        }
        if (r.port() == null || r.port() < 1 || r.port() > 65535) {
            throw new BadRequestResponse("port must be 1-65535");
        }
        if (r.state() == null || !AttackReport.STATES.contains(r.state())) {
            throw new BadRequestResponse("state must be one of " + AttackReport.STATES);
        }

        String mac = null;
        if (r.mac() != null && !r.mac().isBlank()) {
            mac = r.mac().toLowerCase(Locale.ROOT);
            if (!MAC.matcher(mac).matches()) {
                throw new BadRequestResponse("mac must look like aa:bb:cc:dd:ee:ff");
            }
        }
        return new AttackReport(r.sensorId(), r.port(), r.state(), mac, r.srcIp());
    }
}
