package pl.honeypot.server.api;

import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import pl.honeypot.server.store.EventStore;

// GET /api/v1/events - collected events, newest first.
// Optional query params: sensor_id (filter) and limit (most recent N).
public final class EventsQueryHandler implements Handler {

    private final EventStore events;

    public EventsQueryHandler(EventStore events) {
        this.events = events;
    }

    @Override
    public void handle(Context ctx) {
        String sensorId = ctx.queryParam("sensor_id");
        if (sensorId != null && sensorId.isBlank()) {
            sensorId = null;
        }

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

        ctx.json(events.list(sensorId, limit));
    }
}
