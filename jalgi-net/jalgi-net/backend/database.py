"""
JalgiNet – Database Module
===========================
Handles SQLite schema creation, connection management,
and all CRUD operations for alerts, traffic logs, IDS events,
and correlated threats.
"""

import sqlite3
import json
import threading
from datetime import datetime
from config import DB_PATH

# Thread-local storage for per-thread DB connections
_local = threading.local()


def get_connection() -> sqlite3.Connection:
    """Return a thread-local SQLite connection with row_factory set."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row  # Rows behave like dicts
        _local.conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
    return _local.conn


def init_db():
    """Create all tables if they don't already exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # ── Alerts table ──────────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        TEXT NOT NULL,          -- 'DoS' | 'IDS' | 'Correlated'
            severity    TEXT NOT NULL,          -- 'Low' | 'Medium' | 'High' | 'Critical'
            source_ip   TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            extra       TEXT DEFAULT '{}'       -- JSON blob for extra fields
        )
    """)

    # ── Traffic logs table ────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip   TEXT NOT NULL,
            dest_ip     TEXT,
            source_port INTEGER,
            dest_port   INTEGER,
            protocol    TEXT,
            packet_size INTEGER,
            timestamp   TEXT NOT NULL,
            flags       TEXT DEFAULT ''         -- TCP flags if applicable
        )
    """)

    # ── IDS events table ──────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ids_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            source_ip   TEXT NOT NULL,
            dest_ip     TEXT,
            dest_port   INTEGER,
            rule_id     TEXT,
            rule_msg    TEXT,
            severity    TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            raw_log     TEXT DEFAULT ''
        )
    """)

    # ── Correlated threats table ──────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS correlated_threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip   TEXT NOT NULL,
            risk_score  REAL NOT NULL,
            severity    TEXT NOT NULL,
            attack_chain TEXT NOT NULL,         -- JSON array of event types
            description  TEXT NOT NULL,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            event_ids    TEXT DEFAULT '[]'      -- JSON array of linked alert IDs
        )
    """)

    # ── Blocked IPs table ─────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL UNIQUE,
            reason      TEXT,
            blocked_at  TEXT NOT NULL,
            expires_at  TEXT
        )
    """)

    # ── Settings table (key-value store) ─────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # ── Traffic stats (aggregated per-minute counters) ────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            rps         REAL NOT NULL,          -- Requests per second
            total_pkts  INTEGER NOT NULL,
            unique_ips  INTEGER NOT NULL
        )
    """)

    conn.commit()
    print("[DB] Schema initialized.")


# ─────────────────────────────────────────────────────────────────────────────
# ALERT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def insert_alert(alert_type: str, severity: str, source_ip: str,
                 description: str, extra: dict = None) -> int:
    """Insert a new alert and return its ID."""
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"
    extra_json = json.dumps(extra or {})
    cursor = conn.execute(
        "INSERT INTO alerts (type, severity, source_ip, description, timestamp, extra) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (alert_type, severity, source_ip, description, ts, extra_json)
    )
    conn.commit()
    return cursor.lastrowid


def get_alerts(limit: int = 100, offset: int = 0,
               severity: str = None, alert_type: str = None) -> list:
    """Fetch alerts with optional filters."""
    conn = get_connection()
    query = "SELECT * FROM alerts"
    params = []
    conditions = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if alert_type:
        conditions.append("type = ?")
        params.append(alert_type)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_alert_counts() -> dict:
    """Return counts grouped by severity for KPI display."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


# ─────────────────────────────────────────────────────────────────────────────
# TRAFFIC LOG OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def insert_traffic_log(source_ip: str, dest_ip: str, src_port: int,
                       dst_port: int, protocol: str, pkt_size: int,
                       flags: str = "") -> int:
    """Insert a raw packet capture record."""
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"
    cursor = conn.execute(
        "INSERT INTO traffic_logs (source_ip, dest_ip, source_port, dest_port, "
        "protocol, packet_size, timestamp, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (source_ip, dest_ip, src_port, dst_port, protocol, pkt_size, ts, flags)
    )
    conn.commit()
    return cursor.lastrowid


def insert_traffic_stat(rps: float, total_pkts: int, unique_ips: int):
    """Insert an aggregated traffic stat snapshot."""
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"
    conn.execute(
        "INSERT INTO traffic_stats (timestamp, rps, total_pkts, unique_ips) "
        "VALUES (?, ?, ?, ?)",
        (ts, rps, total_pkts, unique_ips)
    )
    conn.commit()


def get_traffic_stats(limit: int = 60) -> list:
    """Return the last N traffic stat snapshots for charting."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return list(reversed([dict(r) for r in rows]))


def get_top_ips_by_traffic(limit: int = 10) -> list:
    """Return the top IPs by packet count from traffic logs."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT source_ip, COUNT(*) as packet_count FROM traffic_logs "
        "GROUP BY source_ip ORDER BY packet_count DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# IDS EVENT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def insert_ids_event(attack_type: str, source_ip: str, dest_ip: str,
                     dest_port: int, rule_id: str, rule_msg: str,
                     severity: str, raw_log: str = "") -> int:
    """Insert a parsed IDS event."""
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"
    cursor = conn.execute(
        "INSERT INTO ids_events (attack_type, source_ip, dest_ip, dest_port, "
        "rule_id, rule_msg, severity, timestamp, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (attack_type, source_ip, dest_ip, dest_port,
         rule_id, rule_msg, severity, ts, raw_log)
    )
    conn.commit()
    return cursor.lastrowid


def get_ids_events(limit: int = 100, offset: int = 0,
                   attack_type: str = None) -> list:
    """Fetch IDS events with optional attack_type filter."""
    conn = get_connection()
    query = "SELECT * FROM ids_events"
    params = []
    if attack_type:
        query += " WHERE attack_type = ?"
        params.append(attack_type)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# CORRELATED THREAT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def upsert_correlated_threat(source_ip: str, risk_score: float,
                              severity: str, attack_chain: list,
                              description: str, event_ids: list) -> int:
    """Insert or update a correlated threat record for a given source IP."""
    conn = get_connection()
    ts_now = datetime.utcnow().isoformat() + "Z"
    existing = conn.execute(
        "SELECT id, first_seen FROM correlated_threats WHERE source_ip = ?",
        (source_ip,)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE correlated_threats SET risk_score=?, severity=?, attack_chain=?, "
            "description=?, last_seen=?, event_ids=? WHERE source_ip=?",
            (risk_score, severity, json.dumps(attack_chain),
             description, ts_now, json.dumps(event_ids), source_ip)
        )
        threat_id = existing["id"]
    else:
        cursor = conn.execute(
            "INSERT INTO correlated_threats (source_ip, risk_score, severity, "
            "attack_chain, description, first_seen, last_seen, event_ids) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (source_ip, risk_score, severity, json.dumps(attack_chain),
             description, ts_now, ts_now, json.dumps(event_ids))
        )
        threat_id = cursor.lastrowid

    conn.commit()
    return threat_id


def get_correlated_threats(limit: int = 50) -> list:
    """Return correlated threats ordered by risk score."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM correlated_threats ORDER BY risk_score DESC LIMIT ?",
        (limit,)
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["attack_chain"] = json.loads(d["attack_chain"])
        d["event_ids"] = json.loads(d["event_ids"])
        result.append(d)
    return result


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKED IPs OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def block_ip(ip: str, reason: str, duration_minutes: int = 60):
    """Add an IP to the simulated block list."""
    from datetime import timedelta
    conn = get_connection()
    now = datetime.utcnow()
    expires = (now + timedelta(minutes=duration_minutes)).isoformat() + "Z"
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (ip, reason, now.isoformat() + "Z", expires)
    )
    conn.commit()


def get_blocked_ips() -> list:
    """Return all currently blocked IPs."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def unblock_ip(ip: str):
    """Remove an IP from the block list."""
    conn = get_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_setting(key: str, default=None) -> str:
    """Get a setting value by key."""
    conn = get_connection()
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    """Upsert a setting value."""
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        (key, str(value))
    )
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# MAINTENANCE OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def clear_all_logs():
    """Wipe all time-series data (alerts, logs, stats, threats)."""
    conn = get_connection()
    for table in ["alerts", "traffic_logs", "ids_events",
                  "correlated_threats", "traffic_stats"]:
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    print("[DB] All logs cleared.")


def get_summary_stats() -> dict:
    """Return dashboard KPIs in a single query batch."""
    conn = get_connection()
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    active_threats = conn.execute(
        "SELECT COUNT(*) FROM correlated_threats WHERE risk_score >= 5"
    ).fetchone()[0]
    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    ids_events = conn.execute("SELECT COUNT(*) FROM ids_events").fetchone()[0]
    critical_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'Critical'"
    ).fetchone()[0]
    severity_counts = get_alert_counts()

    latest_stat = conn.execute(
        "SELECT rps FROM traffic_stats ORDER BY id DESC LIMIT 1"
    ).fetchone()
    current_rps = latest_stat[0] if latest_stat else 0.0

    return {
        "total_alerts":    total_alerts,
        "active_threats":  active_threats,
        "blocked_ips":     blocked_count,
        "ids_events":      ids_events,
        "critical_alerts": critical_alerts,
        "current_rps":     round(current_rps, 2),
        "severity_counts": severity_counts,
    }
