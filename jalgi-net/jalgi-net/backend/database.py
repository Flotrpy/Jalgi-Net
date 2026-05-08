"""
JalgiNet – Database Module
===========================
Handles SQLite or Supabase (PostgreSQL) schema creation,
connection management, and all CRUD operations.
"""

import sqlite3
import json
import threading
import os
from datetime import datetime
from typing import Union

import config

# Conditional import for PostgreSQL
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

# Thread-local storage for per-thread DB connections
_local = threading.local()

class DBConnection:
    """Wrapper to handle both SQLite and PostgreSQL connections."""
    def __init__(self, use_supabase: bool):
        self.use_supabase = use_supabase
        self.conn = None
        self._setup()

    def _setup(self):
        if self.use_supabase:
            if not HAS_PSYCOPG2:
                raise ImportError("psycopg2-binary is required for Supabase/PostgreSQL.")
            self.conn = psycopg2.connect(config.SUPABASE_URL)
            self.conn.autocommit = True
        else:
            self.conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")

    def cursor(self):
        if self.use_supabase:
            return self.conn.cursor(cursor_factory=RealDictCursor)
        return self.conn.cursor()

    def execute(self, query: str, params: tuple = ()):
        # Adapt syntax for specific DB engines
        if self.use_supabase:
            # Replace SQLite ? placeholders with PostgreSQL %s
            query = query.replace("?", "%s")
            # Ensure serial type is used for PRIMARY KEY if hardcoded (though we use SERIAL in init_db)
            query = query.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        else:
            # Ensure PostgreSQL SERIAL is mapped back to SQLite AUTOINCREMENT if shared SQL is used
            query = query.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")

        cursor = self.cursor()
        cursor.execute(query, params)
        return cursor

    def commit(self):
        if not self.use_supabase:
            self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

def get_connection() -> DBConnection:
    """Return a thread-local DB connection wrapper."""
    if not hasattr(_local, "db_conn") or _local.db_conn is None:
        _local.db_conn = DBConnection(config.USE_SUPABASE)
    return _local.db_conn

def init_db():
    """Create all tables if they don't already exist."""
    db = get_connection()

    # Define table schemas (standard SQL with SERIAL PRIMARY KEY, handled by DBConnection.execute for SQLite)
    tables = [
        # Alerts
        """CREATE TABLE IF NOT EXISTS alerts (
            id          SERIAL PRIMARY KEY,
            type        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            source_ip   TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            extra       TEXT DEFAULT '{}'
        )""",
        # Traffic logs
        """CREATE TABLE IF NOT EXISTS traffic_logs (
            id          SERIAL PRIMARY KEY,
            source_ip   TEXT NOT NULL,
            dest_ip     TEXT,
            source_port INTEGER,
            dest_port   INTEGER,
            protocol    TEXT,
            packet_size INTEGER,
            timestamp   TEXT NOT NULL,
            flags       TEXT DEFAULT ''
        )""",
        # IDS events
        """CREATE TABLE IF NOT EXISTS ids_events (
            id          SERIAL PRIMARY KEY,
            attack_type TEXT NOT NULL,
            source_ip   TEXT NOT NULL,
            dest_ip     TEXT,
            dest_port   INTEGER,
            rule_id     TEXT,
            rule_msg    TEXT,
            severity    TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            raw_log     TEXT DEFAULT ''
        )""",
        # Correlated threats
        """CREATE TABLE IF NOT EXISTS correlated_threats (
            id          SERIAL PRIMARY KEY,
            source_ip   TEXT NOT NULL,
            risk_score  REAL NOT NULL,
            severity    TEXT NOT NULL,
            attack_chain TEXT NOT NULL,
            description  TEXT NOT NULL,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            event_ids    TEXT DEFAULT '[]',
            ai_summary   TEXT,
            security_impact TEXT,
            recommended_actions TEXT
        )""",
        # Blocked IPs
        """CREATE TABLE IF NOT EXISTS blocked_ips (
            id          SERIAL PRIMARY KEY,
            ip          TEXT NOT NULL UNIQUE,
            reason      TEXT,
            blocked_at  TEXT NOT NULL,
            expires_at  TEXT
        )""",
        # Settings
        """CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
        # Traffic stats
        """CREATE TABLE IF NOT EXISTS traffic_stats (
            id          SERIAL PRIMARY KEY,
            timestamp   TEXT NOT NULL,
            rps         REAL NOT NULL,
            total_pkts  INTEGER NOT NULL,
            unique_ips  INTEGER NOT NULL
        )"""
    ]

    for table_sql in tables:
        db.execute(table_sql)

    db.commit()
    print(f"[DB] Schema initialized ({'Supabase' if config.USE_SUPABASE else 'SQLite'}).")

# ─────────────────────────────────────────────────────────────────────────────
# ALERT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def insert_alert(alert_type: str, severity: str, source_ip: str,
                 description: str, extra: dict = None) -> int:
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"
    extra_json = json.dumps(extra or {})

    sql = "INSERT INTO alerts (type, severity, source_ip, description, timestamp, extra) VALUES (?, ?, ?, ?, ?, ?)"
    if config.USE_SUPABASE:
        sql += " RETURNING id"

    cursor = conn.execute(sql, (alert_type, severity, source_ip, description, ts, extra_json))

    last_id = 0
    if config.USE_SUPABASE:
        res = cursor.fetchone()
        last_id = res['id'] if res else 0
    else:
        last_id = cursor.lastrowid

    conn.commit()

    # Broadcast new alert via WebSocket
    try:
        from app import socketio
        socketio.emit('new_alert', {
            "type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "description": description
        })
        socketio.emit('update_stats', get_summary_stats())
    except ImportError:
        pass

    return last_id

def get_alerts(limit: int = 100, offset: int = 0,
               severity: str = None, alert_type: str = None) -> list:
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

    rows = conn.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]

def get_alert_counts() -> dict:
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
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"

    sql = ("INSERT INTO traffic_logs (source_ip, dest_ip, source_port, dest_port, "
           "protocol, packet_size, timestamp, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    if config.USE_SUPABASE:
        sql += " RETURNING id"

    cursor = conn.execute(sql, (source_ip, dest_ip, src_port, dst_port, protocol, pkt_size, ts, flags))

    last_id = 0
    if config.USE_SUPABASE:
        res = cursor.fetchone()
        last_id = res['id'] if res else 0
    else:
        last_id = cursor.lastrowid

    conn.commit()
    return last_id

def insert_traffic_stat(rps: float, total_pkts: int, unique_ips: int):
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"
    conn.execute(
        "INSERT INTO traffic_stats (timestamp, rps, total_pkts, unique_ips) "
        "VALUES (?, ?, ?, ?)",
        (ts, rps, total_pkts, unique_ips)
    )
    conn.commit()

def get_traffic_stats(limit: int = 60) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return list(reversed([dict(r) for r in rows]))

def get_top_ips_by_traffic(limit: int = 10) -> list:
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
    conn = get_connection()
    ts = datetime.utcnow().isoformat() + "Z"

    sql = ("INSERT INTO ids_events (attack_type, source_ip, dest_ip, dest_port, "
           "rule_id, rule_msg, severity, timestamp, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    if config.USE_SUPABASE:
        sql += " RETURNING id"

    cursor = conn.execute(
        sql,
        (attack_type, source_ip, dest_ip, dest_port,
         rule_id, rule_msg, severity, ts, raw_log)
    )

    last_id = 0
    if config.USE_SUPABASE:
        res = cursor.fetchone()
        last_id = res['id'] if res else 0
    else:
        last_id = cursor.lastrowid

    conn.commit()
    return last_id

def get_ids_events(limit: int = 100, offset: int = 0,
                   attack_type: str = None) -> list:
    conn = get_connection()
    query = "SELECT * FROM ids_events"
    params = []
    if attack_type:
        query += " WHERE attack_type = ?"
        params.append(attack_type)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = conn.execute(query, tuple(params)).fetchall()
    return [dict(r) for r in rows]

# ─────────────────────────────────────────────────────────────────────────────
# CORRELATED THREAT OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def upsert_correlated_threat(source_ip: str, risk_score: float,
                              severity: str, attack_chain: list,
                              description: str, event_ids: list,
                              ai_data: dict = None) -> int:
    conn = get_connection()
    ts_now = datetime.utcnow().isoformat() + "Z"

    row = conn.execute(
        "SELECT id FROM correlated_threats WHERE source_ip = ?", (source_ip,)
    ).fetchone()

    ai_summary = ai_data.get("summary") if ai_data else None
    ai_impact = ai_data.get("security_impact") if ai_data else None
    ai_actions = ai_data.get("recommended_actions") if ai_data else None

    if row:
        conn.execute(
            "UPDATE correlated_threats SET risk_score=?, severity=?, attack_chain=?, "
            "description=?, last_seen=?, event_ids=?, ai_summary=?, security_impact=?, "
            "recommended_actions=? WHERE source_ip=?",
            (risk_score, severity, json.dumps(attack_chain),
             description, ts_now, json.dumps(event_ids), ai_summary, ai_impact, ai_actions, source_ip)
        )
        threat_id = row["id"]
    else:
        sql = ("INSERT INTO correlated_threats (source_ip, risk_score, severity, "
               "attack_chain, description, first_seen, last_seen, event_ids, "
               "ai_summary, security_impact, recommended_actions) "
               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        if config.USE_SUPABASE:
            sql += " RETURNING id"

        cursor = conn.execute(
            sql,
            (source_ip, risk_score, severity, json.dumps(attack_chain),
             description, ts_now, ts_now, json.dumps(event_ids),
             ai_summary, ai_impact, ai_actions)
        )

        if config.USE_SUPABASE:
            res = cursor.fetchone()
            threat_id = res['id'] if res else 0
        else:
            threat_id = cursor.lastrowid

    conn.commit()

    # Broadcast new alert via WebSocket (Correlated threat is also an alert type)
    if severity in ["High", "Critical"]:
        try:
            from app import socketio
            socketio.emit('new_alert', {
                "type": "Correlated",
                "severity": severity,
                "source_ip": source_ip,
                "description": description
            })
            socketio.emit('update_stats', get_summary_stats())
        except ImportError:
            pass

    return threat_id

def get_correlated_threats(limit: int = 50) -> list:
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
    from datetime import timedelta
    conn = get_connection()
    now = datetime.utcnow()
    expires = (now + timedelta(minutes=duration_minutes)).isoformat() + "Z"

    # PostgreSQL doesn't support INSERT OR REPLACE, use ON CONFLICT
    if config.USE_SUPABASE:
        conn.execute(
            "INSERT INTO blocked_ips (ip, reason, blocked_at, expires_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT (ip) DO UPDATE SET "
            "reason=EXCLUDED.reason, blocked_at=EXCLUDED.blocked_at, expires_at=EXCLUDED.expires_at",
            (ip, reason, now.isoformat() + "Z", expires)
        )
    else:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (ip, reason, now.isoformat() + "Z", expires)
        )
    conn.commit()

def get_blocked_ips() -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]

def unblock_ip(ip: str):
    conn = get_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()

# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def get_setting(key: str, default=None) -> str:
    conn = get_connection()
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    conn = get_connection()
    if config.USE_SUPABASE:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            (key, str(value))
        )
    else:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, str(value))
        )
    conn.commit()

# ─────────────────────────────────────────────────────────────────────────────
# MAINTENANCE OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def clear_all_logs():
    conn = get_connection()
    for table in ["alerts", "traffic_logs", "ids_events",
                  "correlated_threats", "traffic_stats"]:
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    print("[DB] All logs cleared.")

def get_summary_stats() -> dict:
    conn = get_connection()
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    total_alerts = total_alerts[0] if total_alerts else 0

    active_threats = conn.execute(
        "SELECT COUNT(*) FROM correlated_threats WHERE risk_score >= 5"
    ).fetchone()
    active_threats = active_threats[0] if active_threats else 0

    blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()
    blocked_count = blocked_count[0] if blocked_count else 0

    ids_events = conn.execute("SELECT COUNT(*) FROM ids_events").fetchone()
    ids_events = ids_events[0] if ids_events else 0

    critical_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE severity = 'Critical'"
    ).fetchone()
    critical_alerts = critical_alerts[0] if critical_alerts else 0

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
