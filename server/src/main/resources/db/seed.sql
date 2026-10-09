-- Development seed: one sensor matching the agent default (sensor-01).
-- Loaded only when db.seed=true in server.properties.
INSERT OR IGNORE INTO sensors (sensor_id, hostname, timeout_sec, heartbeat_sec, srv_port)
VALUES ('sensor-01', 'honeypot-agent-stub', 5, 30, 8000);

INSERT OR IGNORE INTO sensor_ports (sensor_id, port) VALUES ('sensor-01', 22);
INSERT OR IGNORE INTO sensor_ports (sensor_id, port) VALUES ('sensor-01', 23);
INSERT OR IGNORE INTO sensor_ports (sensor_id, port) VALUES ('sensor-01', 80);
INSERT OR IGNORE INTO sensor_ports (sensor_id, port) VALUES ('sensor-01', 2222);
