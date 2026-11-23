import os
import re
import json
import time
import socket
import ipaddress
import sqlite3
import subprocess
import urllib.request
from urllib.parse import urlparse
import asyncio
from collections import deque
from fastapi import Request

DB_PATH = "adhdf_enterprise.db"
IP_RISK_PROFILES = {}
FAILED_AUTH_ATTEMPTS = {}
REQUEST_TIMESTAMPS = {}

def init_security_tables():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS persistent_bans (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            risk_score INTEGER,
            banned_at REAL
        )
    """)
    conn.commit()
    conn.close()

init_security_tables()

def sanitize_log_text(text: str, max_len: int = 500) -> str:
    if not text:
        return ""
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\x1b\[[0-9;]*[mGKH]', '', str(text))
    return cleaned[:max_len]

def get_real_attacker_ip(request: Request) -> str:
    direct_ip = request.client.host if request.client else "0.0.0.0"
    trusted_proxies = [x.strip() for x in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if x.strip()]
    
    if direct_ip in trusted_proxies:
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
            
    return direct_ip

def is_ip_whitelisted(ip: str) -> bool:
    whitelist = [x.strip() for x in os.getenv("WHITELIST_IPS", "127.0.0.1,::1").split(",") if x.strip()]
    return ip in whitelist

def enforce_os_firewall_block(ip: str):
    """L3/L4 İşletim Sistemi Güvenlik Duvarı (Windows Defender Firewall) Otomatik Bloklama."""
    if os.getenv("OS_FIREWALL_BLOCK", "false").lower() != "true":
        return
    if is_ip_whitelisted(ip):
        return
    try:
        # Komut enjeksiyonuna karşı IP adresini Python ipaddress kütüphanesiyle katı doğrula
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return
        safe_ip = str(ip_obj)
        rule_name = f"AdHDF_AutoBlock_{safe_ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={safe_ip}"
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except Exception:
        pass

def check_rate_limit(ip: str) -> bool:
    if is_ip_whitelisted(ip):
        return False
    max_rpm = int(os.getenv("RATE_LIMIT_RPM", "30"))
    now = time.time()
    q = REQUEST_TIMESTAMPS.setdefault(ip, deque())
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= max_rpm:
        persist_ip_ban(ip, "Rate Limit Exceeded (Automated Flood)", 90)
        return True
    q.append(now)
    return False

def persist_ip_ban(ip: str, reason: str, score: int):
    if is_ip_whitelisted(ip):
        return
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        conn.execute(
            "INSERT OR REPLACE INTO persistent_bans (ip, reason, risk_score, banned_at) VALUES (?, ?, ?, ?)",
            (ip, sanitize_log_text(reason, 120), score, time.time())
        )
        conn.commit()
        conn.close()
        enforce_os_firewall_block(ip)
    except Exception:
        pass

def is_ip_blocked(ip: str) -> bool:
    if is_ip_whitelisted(ip):
        return False
    if os.getenv("ACTIVE_BLOCK_ENABLED", "true").lower() != "true":
        return False
    threshold = int(os.getenv("BLOCK_THRESHOLD", "75"))
    profile = IP_RISK_PROFILES.get(ip)
    if profile and profile["score"] >= threshold:
        return True
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        row = conn.execute("SELECT 1 FROM persistent_bans WHERE ip = ?", (ip,)).fetchone()
        conn.close()
        return bool(row)
    except Exception:
        return False

def check_auth_lockout(ip: str) -> bool:
    record = FAILED_AUTH_ATTEMPTS.get(ip)
    if not record:
        return False
    if time.time() < record["locked_until"]:
        return True
    if time.time() >= record["locked_until"] and record["count"] >= 5:
        del FAILED_AUTH_ATTEMPTS[ip]
    return False

def register_failed_auth(ip: str):
    record = FAILED_AUTH_ATTEMPTS.get(ip, {"count": 0, "locked_until": 0})
    record["count"] += 1
    if record["count"] >= 5:
        record["locked_until"] = time.time() + 900
        persist_ip_ban(ip, "SOC Admin Brute-Force Attempt", 100)
    FAILED_AUTH_ATTEMPTS[ip] = record

def clear_failed_auth(ip: str):
    if ip in FAILED_AUTH_ATTEMPTS:
        del FAILED_AUTH_ATTEMPTS[ip]

def calculate_threat_score(ip: str, event_type: str, confidence: str) -> dict:
    profile = IP_RISK_PROFILES.get(ip, {"score": 0, "hits": 0, "canary_triggered": False})
    profile["hits"] += 1

    weight_map = {
        "Directory Fuzzing / Recon": 15,
        "Sensitive File Exposure": 35,
        "Credential / Key Harvesting": 55,
        "Path Traversal / LFI": 45,
        "SQL Injection": 50,
        "Command Injection / RCE": 65,
        "SSRF / Cloud Metadata Probe": 70,
        "CRITICAL_CANARY_TRIGGERED": 100
    }
    added_score = weight_map.get(event_type, 10)
    if confidence == "High":
        added_score += 10

    if event_type == "CRITICAL_CANARY_TRIGGERED":
        profile["score"] = 100
        profile["canary_triggered"] = True
    else:
        profile["score"] = min(95, profile["score"] + added_score)

    IP_RISK_PROFILES[ip] = profile

    threshold = int(os.getenv("BLOCK_THRESHOLD", "75"))
    if profile["score"] >= threshold:
        persist_ip_ban(ip, event_type, profile["score"])

    severity = "LOW"
    if profile["score"] >= 80:
        severity = "CRITICAL"
    elif profile["score"] >= 50:
        severity = "HIGH"
    elif profile["score"] >= 25:
        severity = "MEDIUM"

    return {
        "risk_score": profile["score"],
        "severity": severity,
        "total_hits_from_ip": profile["hits"]
    }

def format_cef_event(event_data: dict) -> str:
    """Splunk / QRadar / Wazuh / Elastic SIEM uyumlu ArcSight CEF çıktısı üretir."""
    sev_map = {"LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
    cef_sev = sev_map.get(event_data.get("severity", "LOW"), 3)
    evt_name = str(event_data.get("event_type", "Unknown")).replace("|", "\\|")
    src_ip = event_data.get("attacker_ip", "0.0.0.0")
    req_path = str(event_data.get("target_path", "/")).replace("=", "\\=")
    tool = str(event_data.get("detected_tool", "Unknown")).replace("=", "\\=")
    canary = event_data.get("canary_id", "none")
    score = event_data.get("risk_score", 0)
    return (
        f"CEF:0|AdHDF|EnterpriseDeception|1.2|{evt_name}|{evt_name}|{cef_sev}|"
        f"src={src_ip} request={req_path} cs1={tool} cs1Label=AttackerTool "
        f"cs2={canary} cs2Label=CanaryToken cn1={score} cn1Label=RiskScore"
    )

def _is_safe_webhook_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            return False
        resolved_ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(resolved_ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
    except Exception:
        return False

async def dispatch_webhook_alert(event_data: dict):
    cef_line = format_cef_event(event_data)
    try:
        with open("adhdf_siem.cef.log", "a", encoding="utf-8") as f:
            f.write(cef_line + "\n")
    except Exception:
        pass

    siem_host = os.getenv("SIEM_SYSLOG_HOST", "").strip()
    siem_port = int(os.getenv("SIEM_SYSLOG_PORT", "514"))
    if siem_host:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(f"<134>{cef_line}".encode("utf-8"), (siem_host, siem_port))
            sock.close()
        except Exception:
            pass

    webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not webhook_url or not _is_safe_webhook_url(webhook_url):
        return

    payload = {
        "content": (
            f"🚨 **[AdHDF SOC ALERT - {event_data['severity']}]**\n"
            f"**Olay:** `{event_data['event_type']}` | **Risk Skoru:** `{event_data['risk_score']}/100`\n"
            f"**Saldırgan IP:** `{event_data['attacker_ip']}` | **Araç:** `{event_data['detected_tool']}`\n"
            f"**Hedef:** `{event_data['target_path']}` | **Canary ID:** `{event_data['canary_id']}`"
        )
    }

    def _send():
        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "AdHDF-SOC-Notifier/1.2"}
            )
            urllib.request.urlopen(req, timeout=4)
        except Exception:
            pass

    await asyncio.to_thread(_send)
