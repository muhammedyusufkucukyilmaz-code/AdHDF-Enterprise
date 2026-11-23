import os
import re
import time
import ipaddress
import subprocess
from collections import defaultdict
from fastapi import Request

_RATE_HISTORY = defaultdict(list)
_FAILED_AUTH = defaultdict(list)

def sanitize_log_text(text: str, max_len: int = 500) -> str:
    if not text:
        return ""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", str(text))
    return cleaned[:max_len]

def get_real_attacker_ip(request: Request) -> str:
    client_host = request.client.host if request.client else "127.0.0.1"
    trusted_proxies = {ip.strip() for ip in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if ip.strip()}
    if client_host in trusted_proxies:
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return client_host

def is_whitelisted(ip: str) -> bool:
    whitelist = {w.strip() for w in os.getenv("WHITELIST_IPS", "127.0.0.1,::1").split(",") if w.strip()}
    return ip in whitelist

def check_rate_limit(ip: str) -> bool:
    if is_whitelisted(ip):
        return False
    rpm = int(os.getenv("RATE_LIMIT_RPM", "30"))
    now = time.time()
    _RATE_HISTORY[ip] = [t for t in _RATE_HISTORY[ip] if now - t < 60]
    _RATE_HISTORY[ip].append(now)
    if len(_RATE_HISTORY[ip]) > rpm:
        apply_os_firewall_block(ip)
        return True
    return False

def check_auth_lockout(ip: str) -> bool:
    now = time.time()
    _FAILED_AUTH[ip] = [t for t in _FAILED_AUTH[ip] if now - t < 900]
    return len(_FAILED_AUTH[ip]) >= 5

def register_failed_auth(ip: str):
    _FAILED_AUTH[ip].append(time.time())

def clear_failed_auth(ip: str):
    _FAILED_AUTH.pop(ip, None)

def apply_os_firewall_block(ip: str) -> bool:
    if os.getenv("OS_FIREWALL_BLOCK", "true").lower() != "true" or is_whitelisted(ip):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_private:
            return False
        rule_name = f"AdHDF_Block_{ip_obj.compressed}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_obj.compressed}"],
            capture_output=True, text=True, timeout=5
        )
        return True
    except Exception:
        return False

def remove_os_firewall_block(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        rule_name = f"AdHDF_Block_{ip_obj.compressed}"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=5
        )
        _RATE_HISTORY.pop(ip_obj.compressed, None)
        return True
    except Exception:
        return False

def is_ip_blocked(ip: str) -> bool:
    if is_whitelisted(ip) or os.getenv("ACTIVE_BLOCK_ENABLED", "true").lower() != "true":
        return False
    from app.database import check_db_blocklist
    return check_db_blocklist(ip, int(os.getenv("BLOCK_THRESHOLD", "75")))

def calculate_threat_score(ip: str, attack_type: str, fp_confidence: int) -> dict:
    base_scores = {
        "CRITICAL_CANARY_TRIGGERED": 100,
        "Command Injection / RCE": 95,
        "Credential / Key Harvesting": 90,
        "SSRF / Cloud Metadata Probe": 85,
        "SQL Injection": 80,
        "Path Traversal / LFI": 75,
        "Sensitive File Exposure": 70,
        "Directory Fuzzing / Recon": 40
    }
    score = min(100, base_scores.get(attack_type, 40) + int(fp_confidence * 0.25))
    blocked = False
    if score >= int(os.getenv("BLOCK_THRESHOLD", "75")) and not is_whitelisted(ip):
        blocked = apply_os_firewall_block(ip)
    return {"risk_score": score, "os_blocked": blocked}

def format_cef_event(inc: dict) -> str:
    sev = min(10, max(1, int(inc.get("risk_score", 50) / 10)))
    return (
        f"CEF:0|MuhammedYusufKucukyilmaz|AdHDF_Enterprise|2.0|{inc.get('event_type','PROBE')}|"
        f"{inc.get('event_type','PROBE')}|{sev}|src={inc.get('ip','0.0.0.0')} "
        f"request={inc.get('path','/')} cs1={inc.get('canary_id','none')} cs1Label=CanaryID"
    )

async def dispatch_webhook_alert(entry: dict):
    webhook = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not webhook:
        return
    try:
        import urllib.request, json
        data = json.dumps({"content": f"[AdHDF Alert] {entry.get('event_type')} from {entry.get('ip')} (Score: {entry.get('risk_score')})"}).encode("utf-8")
        req = urllib.request.Request(webhook, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass
