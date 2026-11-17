package pl.honeypot.server;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

// Server settings loaded from a .properties file.
//
// The receiver speaks HTTPS only: the C agent verifies the TLS chain and the
// receiver IP in the certificate SAN, and that verification cannot be turned
// off agent-side. So a keystore is mandatory.
public record ServerConfig(
        String bindAddress,
        int port,
        Path dataDir,
        Path keystore,
        String keystorePassword,
        Path dashboardDir) {

    public static ServerConfig load(Path file) throws IOException {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file)) {
            p.load(r);
        }

        String keystore = p.getProperty("server.keystore");
        if (keystore == null || keystore.isBlank()) {
            throw new IOException("server.keystore is required (PKCS12 with the TLS cert/key); "
                    + "run scripts/gen-certs.sh to create one");
        }

        String password = p.getProperty("server.keystore.password", "");
        if (password.isEmpty()) {
            throw new IOException("server.keystore.password must not be empty");
        }
        if (!Files.isRegularFile(Path.of(keystore))) {
            throw new IOException("keystore file not found: " + keystore);
        }

        return new ServerConfig(
                p.getProperty("server.bind", "127.0.0.1"),
                Integer.parseInt(p.getProperty("server.port", "8443")),
                Path.of(p.getProperty("data.dir", "data")),
                Path.of(keystore),
                p.getProperty("server.keystore.password", ""),
                Path.of(p.getProperty("dashboard.dir", "../dashboard")));
    }
}
