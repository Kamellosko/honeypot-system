package pl.honeypot.server.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import pl.honeypot.server.model.AgentConfig;

public final class SensorRepository {

    private final Database db;

    public SensorRepository(Database db) {
        this.db = db;
    }

    // Builds the agent config from sensors + sensor_ports
    public Optional<AgentConfig> findConfig(String sensorId) throws SQLException {
        try (Connection c = db.connect()) {
            int timeout, heartbeat, srvPort;
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT timeout_sec, heartbeat_sec, srv_port FROM sensors WHERE sensor_id = ?")) {
                ps.setString(1, sensorId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    timeout = rs.getInt(1);
                    heartbeat = rs.getInt(2);
                    srvPort = rs.getInt(3);
                }
            }

            List<Integer> ports = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT port FROM sensor_ports WHERE sensor_id = ? ORDER BY port")) {
                ps.setString(1, sensorId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        ports.add(rs.getInt(1));
                    }
                }
            }

            String portList = ports.stream().map(String::valueOf).collect(Collectors.joining(","));
            return Optional.of(new AgentConfig(sensorId, ports.size(), timeout, heartbeat, srvPort, portList));
        }
    }

    public boolean exists(String sensorId) throws SQLException {
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement("SELECT 1 FROM sensors WHERE sensor_id = ?")) {
            ps.setString(1, sensorId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    // Any message from the agent counts as a sign of life
    public void touch(String sensorId) throws SQLException {
        try (Connection c = db.connect();
             PreparedStatement ps = c.prepareStatement(
                     "UPDATE sensors SET status = 'online', "
                             + "last_seen = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE sensor_id = ?")) {
            ps.setString(1, sensorId);
            ps.executeUpdate();
        }
    }
}
