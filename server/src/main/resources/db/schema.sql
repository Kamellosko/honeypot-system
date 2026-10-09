-- Honeypot server - SQLite schema
-- Idempotent: executed on every server start (CREATE ... IF NOT EXISTS).
-- Timestamps are stored as ISO-8601 UTC text, e.g. 2026-10-09T14:03:21Z
-- NOTE: do not put semicolons inside comments, the loader splits on them.

-- Honeypots known to the server. A sensor must exist here before its agent
-- can fetch a config or report events (pre-provisioned by the admin).
CREATE TABLE IF NOT EXISTS sensors (
    sensor_id      TEXT    PRIMARY KEY,
    hostname       TEXT,
    timeout_sec    INTEGER NOT NULL DEFAULT 5    CHECK (timeout_sec > 0),
    heartbeat_sec  INTEGER NOT NULL DEFAULT 30   CHECK (heartbeat_sec > 0),
    srv_port       INTEGER NOT NULL DEFAULT 8000 CHECK (srv_port BETWEEN 1 AND 65535),
    status         TEXT    NOT NULL DEFAULT 'unknown'
                           CHECK (status IN ('unknown', 'online', 'offline')),
    last_seen      TEXT,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Decoy ports each sensor should listen on. port_count and the "ports"
-- string in the agent config are derived from this table.
CREATE TABLE IF NOT EXISTS sensor_ports (
    sensor_id  TEXT    NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    PRIMARY KEY (sensor_id, port)
);

-- Connection attempts reported by agents (POST /api/v1/events).
CREATE TABLE IF NOT EXISTS events (
    event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id     TEXT    NOT NULL REFERENCES sensors(sensor_id),
    dst_port      INTEGER NOT NULL CHECK (dst_port BETWEEN 1 AND 65535),
    sensor_state  TEXT    NOT NULL,
    attacker_mac  TEXT    CHECK (attacker_mac IS NULL OR length(attacker_mac) = 17),
    src_ip        TEXT,
    received_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_events_sensor_time ON events(sensor_id, received_at);
CREATE INDEX IF NOT EXISTS idx_events_mac         ON events(attacker_mac);
CREATE INDEX IF NOT EXISTS idx_events_src_ip      ON events(src_ip);

-- Phase 1: heartbeat history (sensors.last_seen holds the latest one).
CREATE TABLE IF NOT EXISTS heartbeats (
    heartbeat_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id          TEXT    NOT NULL REFERENCES sensors(sensor_id) ON DELETE CASCADE,
    events_since_last  INTEGER NOT NULL DEFAULT 0,
    uptime_sec         INTEGER NOT NULL DEFAULT 0,
    received_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_heartbeats_sensor_time ON heartbeats(sensor_id, received_at);

-- Fault reports from agents (POST /api/v1/errors), the second message type.
CREATE TABLE IF NOT EXISTS error_reports (
    report_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id     TEXT    NOT NULL REFERENCES sensors(sensor_id),
    sensor_state  TEXT    NOT NULL,
    error_id      INTEGER NOT NULL,
    received_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_error_reports_sensor_time ON error_reports(sensor_id, received_at);

-- Phase 3: indicators of compromise served to agents (GET /api/v1/ioc).
CREATE TABLE IF NOT EXISTS ioc (
    ioc_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type   TEXT    NOT NULL CHECK (indicator_type IN ('ip', 'mac')),
    value            TEXT    NOT NULL,
    reason           TEXT,
    source_event_id  INTEGER REFERENCES events(event_id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at       TEXT,
    UNIQUE (indicator_type, value)
);
