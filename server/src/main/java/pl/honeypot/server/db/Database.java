package pl.honeypot.server.db;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.stream.Collectors;
import org.sqlite.SQLiteConfig;

// Opens SQLite connections and runs SQL scripts from the classpath
public final class Database {

    private final String url;
    private final SQLiteConfig sqliteConfig = new SQLiteConfig();

    public Database(Path file) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        this.url = "jdbc:sqlite:" + file;
        // Foreign keys are off by default in SQLite and must be enabled per connection
        sqliteConfig.enforceForeignKeys(true);
        sqliteConfig.setBusyTimeout(5000);
    }

    public Connection connect() throws SQLException {
        return DriverManager.getConnection(url, sqliteConfig.toProperties());
    }

    // Executes a ;-separated script. Full-line "--" comments are skipped.
    public void runScript(String resource) throws IOException, SQLException {
        String sql;
        try (InputStream in = Database.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Missing resource: " + resource);
            }
            sql = new String(in.readAllBytes(), StandardCharsets.UTF_8)
                    .lines()
                    .filter(line -> !line.strip().startsWith("--"))
                    .collect(Collectors.joining("\n"));
        }

        try (Connection c = connect(); Statement st = c.createStatement()) {
            for (String stmt : sql.split(";")) {
                if (!stmt.isBlank()) {
                    st.execute(stmt);
                }
            }
        }
    }
}
