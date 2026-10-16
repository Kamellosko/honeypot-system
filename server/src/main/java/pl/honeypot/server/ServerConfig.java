package pl.honeypot.server;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

// Server settings loaded from a .properties file
public record ServerConfig(String bindAddress, int port, Path sensorsFile, Path dataDir) {

    public static ServerConfig load(Path file) throws IOException {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file)) {
            p.load(r);
        }
        return new ServerConfig(
                p.getProperty("server.bind", "0.0.0.0"),
                Integer.parseInt(p.getProperty("server.port", "8000")),
                Path.of(p.getProperty("sensors.file", "config/sensors.json")),
                Path.of(p.getProperty("data.dir", "data")));
    }
}
