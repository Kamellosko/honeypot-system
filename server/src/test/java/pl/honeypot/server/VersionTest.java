package pl.honeypot.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import pl.honeypot.server.api.VersionHandler;

class VersionTest {
    @Test
    void pomVersionMatchesVersionFile() throws Exception {
        String file = Files.readString(Path.of("../VERSION")).trim();
        Matcher m = Pattern.compile("<artifactId>honeypot-server</artifactId>\\s*<version>([^<]+)</version>")
                .matcher(Files.readString(Path.of("pom.xml")));
        assertTrue(m.find());
        assertEquals(file, m.group(1));
    }

    @Test
    void versionEndpointReportsServerAndSchemaVersions() throws Exception {
        Javalin app = Javalin.create().get("/api/version", new VersionHandler("9.9.9")).start(0);
        try {
            HttpResponse<String> r = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + app.port() + "/api/version")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, r.statusCode());
            JsonNode j = new ObjectMapper().readTree(r.body());
            assertEquals("9.9.9", j.get("server_version").asText());
            assertEquals(1, j.get("schema_versions").get(0).asInt());
            assertEquals(2, j.get("schema_versions").get(1).asInt());
        } finally {
            app.stop();
        }
    }
}
