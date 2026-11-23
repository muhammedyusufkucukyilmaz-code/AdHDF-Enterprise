import os
import sqlite3
from datetime import datetime, timezone, timedelta

DB_PATH = "adhdf_enterprise.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                ip TEXT NOT NULL,
                path TEXT NOT NULL,
                tool_detected TEXT,
                risk_score INTEGER DEFAULT 0,
                canary_id TEXT,
                payload TEXT,
                ai_output TEXT,
                unbanned INTEGER DEFAULT 0
            )
        """)
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(incidents)").fetchall()]
        if "unbanned" not in cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN unbanned INTEGER DEFAULT 0")
        conn.commit()

def purge_expired_bans():
    ttl_hours = int(os.getenv("BAN_TTL_HOURS", "24"))
    if ttl_hours <= 0:
        return
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=ttl_hours)).isoformat()
    with get_conn() as conn:
        expired = conn.execute(
            "SELECT DISTINCT ip FROM incidents WHERE unbanned = 0 AND timestamp < ?",
            (cutoff,)
        ).fetchall()
        if expired:
            from app.threat_intel import remove_os_firewall_block
            for row in expired:
                remove_os_firewall_block(row["ip"])
            conn.execute("UPDATE incidents SET unbanned = 1 WHERE unbanned = 0 AND timestamp < ?", (cutoff,))
            conn.commit()

def check_db_blocklist(ip: str, min_score: int = 75) -> bool:
    purge_expired_bans()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT MAX(risk_score) as max_s FROM incidents WHERE ip = ? AND unbanned = 0",
            (ip,)
        ).fetchone()
        return bool(row and row["max_s"] is not None and row["max_s"] >= min_score)

def unban_ip_address(ip: str):
    from app.threat_intel import remove_os_firewall_block
    remove_os_firewall_block(ip)
    with get_conn() as conn:
        conn.execute("UPDATE incidents SET unbanned = 1 WHERE ip = ?", (ip,))
        conn.commit()

def get_malicious_blocklist(min_score: int = 75):
    purge_expired_bans()
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT ip, MAX(risk_score) as max_risk_score, MAX(timestamp) as last_seen, COUNT(*) as hit_count
            FROM incidents
            WHERE unbanned = 0
            GROUP BY ip
            HAVING max_risk_score >= ?
            ORDER BY last_seen DESC
        """, (min_score,)).fetchall()
        return [dict(r) for r in rows]

def get_all_incidents():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 500").fetchall()
        return [dict(r) for r in rows]

def get_dashboard_metrics():
    purge_expired_bans()
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()["c"]
        canaries = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE event_type = 'CRITICAL_CANARY_TRIGGERED'").fetchone()["c"]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT ip) as c FROM incidents").fetchone()["c"]
        blocked_ips = len(get_malicious_blocklist(int(os.getenv("BLOCK_THRESHOLD", "75"))))
        recent = [dict(r) for r in conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 25").fetchall()]
        tools = [dict(r) for r in conn.execute("SELECT COALESCE(tool_detected, 'Unknown') as tool, COUNT(*) as count FROM incidents GROUP BY tool ORDER BY count DESC LIMIT 6").fetchall()]
        return {
            "total_events": total,
            "canary_triggers": canaries,
            "unique_ips": unique_ips,
            "blocked_ips": blocked_ips,
            "blocklist": get_malicious_blocklist(int(os.getenv("BLOCK_THRESHOLD", "75"))),
            "recent_incidents": recent,
            "tool_distribution": tools
        }
