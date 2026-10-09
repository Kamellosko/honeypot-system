package pl.honeypot.server.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import pl.honeypot.server.model.Heartbeat;

public final class HeartbeatRepository {

    private final Database db;

    public HeartbeatRepository(Database db) {
        this.db = db;
    }

    public void insert(Heartbeat hb) throws SQLException {
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO heartbeats (sensor_id, events_since_last, uptime_sec) VALUES (?, ?, ?)")) {
            ps.setString(1, hb.sensorId());
            ps.setInt(2, hb.eventsSinceLast());
            ps.setLong(3, hb.uptimeSec());
            ps.executeUpdate();
        }
    }
}
