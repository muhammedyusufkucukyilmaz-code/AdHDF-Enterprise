import sqlite3
import json
from datetime import datetime, timezone

DB_PATH = "adhdf_enterprise.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            attacker_ip TEXT NOT NULL,
            target_path TEXT NOT NULL,
            detected_tool TEXT,
            confidence TEXT,
            risk_score INTEGER,
            severity TEXT,
            canary_id TEXT,
            payload TEXT,
            ai_output TEXT,
            headers_json TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attacker_ip ON security_events(attacker_ip);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp DESC);")
    conn.commit()
    conn.close()

def insert_security_event(entry: dict):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO security_events (
            timestamp, event_type, attacker_ip, target_path, detected_tool,
            confidence, risk_score, severity, canary_id, payload, ai_output, headers_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry["timestamp"],
        entry["event_type"],
        entry["attacker_ip"],
        entry["target_path"],
        entry["detected_tool"],
        entry["confidence"],
        entry["risk_score"],
        entry["severity"],
        entry["canary_id"],
        entry["payload"],
        entry["ai_output"],
        json.dumps(entry.get("headers", {}))
    ))
    conn.commit()
    conn.close()

def get_dashboard_metrics() -> dict:
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICAL'").fetchone()[0]
    canary_hits = conn.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'CRITICAL_CANARY_TRIGGERED'").fetchone()[0]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT attacker_ip) FROM security_events").fetchone()[0]

    recent_rows = conn.execute("""
        SELECT id, timestamp, event_type, attacker_ip, target_path, detected_tool, risk_score, severity, canary_id
        FROM security_events ORDER BY id DESC LIMIT 25
    """).fetchall()

    tool_rows = conn.execute("""
        SELECT detected_tool, COUNT(*) as count FROM security_events
        GROUP BY detected_tool ORDER BY count DESC LIMIT 6
    """).fetchall()

    conn.close()
    return {
        "total_events": total,
        "critical_events": critical,
        "canary_triggers": canary_hits,
        "unique_attackers": unique_ips,
        "recent_events": [dict(r) for r in recent_rows],
        "tool_distribution": [dict(r) for r in tool_rows]
    }

def get_all_incidents() -> list:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM security_events ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_malicious_blocklist(min_score: int = 75) -> list:
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT attacker_ip as ip, MAX(risk_score) as max_risk_score, MAX(timestamp) as last_seen
        FROM security_events
        WHERE risk_score >= ?
        GROUP BY attacker_ip
        ORDER BY max_risk_score DESC
    """, (min_score,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

insert_incident = insert_security_event

