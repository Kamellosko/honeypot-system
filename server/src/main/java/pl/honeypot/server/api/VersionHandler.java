package pl.honeypot.server.api;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import java.util.List;
import java.util.Map;

// GET /api/version: server build version and the report schema versions it accepts.
public final class VersionHandler implements Handler {
    private final String serverVersion;

    public VersionHandler(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    @Override
    public void handle(Context ctx) {
        ctx.json(Map.of("server_version", serverVersion, "schema_versions", List.of(1, 2)));
    }
}
