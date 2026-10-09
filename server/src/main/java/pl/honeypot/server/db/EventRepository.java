package pl.honeypot.server.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import pl.honeypot.server.model.AttackReport;

public final class EventRepository {

    private final Database db;

    public EventRepository(Database db) {
        this.db = db;
    }

    // Returns the generated event_id
    public long insert(AttackReport r) throws SQLException {
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO events (sensor_id, dst_port, sensor_state, attacker_mac, src_ip) "
                             + "VALUES (?, ?, ?, ?, ?)",
                     Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, r.sensorId());
            ps.setInt(2, r.port());
            ps.setString(3, r.state());
            ps.setString(4, r.mac());
            ps.setString(5, r.srcIp());
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                return keys.next() ? keys.getLong(1) : -1;
            }
        }
    }
}
