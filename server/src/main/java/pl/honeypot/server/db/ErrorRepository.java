package pl.honeypot.server.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import pl.honeypot.server.model.ErrorReport;

public final class ErrorRepository {

    private final Database db;

    public ErrorRepository(Database db) {
        this.db = db;
    }

    // Returns the generated report_id
    public long insert(ErrorReport r) throws SQLException {
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO error_reports (sensor_id, sensor_state, error_id) VALUES (?, ?, ?)",
                     Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, r.sensorId());
            ps.setString(2, r.state());
            ps.setInt(3, r.errorId());
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                return keys.next() ? keys.getLong(1) : -1;
            }
        }
    }
}
