package pl.honeypot.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.staticfiles.Location;
import java.nio.file.Files;
import java.nio.file.Path;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import pl.honeypot.server.api.AgentsHandler;
import pl.honeypot.server.api.AttackersHandler;
import pl.honeypot.server.api.EventsQueryHandler;
import pl.honeypot.server.api.ReportHandler;
import pl.honeypot.server.api.StatsHandler;
import pl.honeypot.server.store.JsonlLog;
import pl.honeypot.server.store.ReportStore;

public final class Main {

    public static void main(String[] args) throws Exception {
        Path configFile = Path.of(args.length > 0 ? args[0] : "config/server.properties");
        ServerConfig cfg = ServerConfig.load(configFile);

        ObjectMapper mapper = new ObjectMapper();

        // Every agent report lands in data/events.jsonl, deduplicated by report_id.
        ReportStore reports = new ReportStore(
                new JsonlLog(cfg.dataDir().resolve("events.jsonl"), mapper, "event_id"),
                cfg.confirmAccounts(), cfg.breadcrumbMarker());

        boolean serveDashboard = Files.isDirectory(cfg.dashboardDir());

        Javalin app = Javalin.create(c -> {
            c.showJavalinBanner = false;
            // Agent reports can carry file diffs; the 1 MB default would reject them
            // with a 4xx and the agent would retry the same report forever.
            c.http.maxRequestSize = 32L * 1024 * 1024;
            c.jetty.addConnector((server, httpConfig) -> {
                SslContextFactory.Server ssl = new SslContextFactory.Server();
                ssl.setKeyStorePath(cfg.keystore().toAbsolutePath().toString());
                ssl.setKeyStorePassword(cfg.keystorePassword());
                ssl.setKeyStoreType("PKCS12");
                ssl.setIncludeProtocols("TLSv1.2", "TLSv1.3");
                ServerConnector connector = new ServerConnector(server,
                        new SslConnectionFactory(ssl, "http/1.1"),
                        new HttpConnectionFactory(httpConfig));
                connector.setHost(cfg.bindAddress());
                connector.setPort(cfg.port());
                return connector;
            });
            // Serve the dashboard from the same origin, so no CORS is needed.
            if (serveDashboard) {
                c.staticFiles.add(s -> {
                    s.directory = cfg.dashboardDir().toAbsolutePath().toString();
                    s.location = Location.EXTERNAL;
                });
            }
        });

        // Agent -> server. The frozen agent posts to /events (hardcoded in the C
        // agent's port.c), so that path stays; /api/events is the same ingress
        // under the unified /api/* namespace.
        ReportHandler ingest = new ReportHandler(reports, cfg.port());
        app.post("/events", ingest);
        app.post("/api/events", ingest);

        // Server -> operator (read-only views for the dashboard).
        app.get("/api/agents", new AgentsHandler(reports));
        app.get("/api/events", new EventsQueryHandler(reports));
        app.get("/api/stats", new StatsHandler(reports));
        app.get("/api/attackers", new AttackersHandler(reports));

        app.start();
    }
}
