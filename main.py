import os
import sys
import re
import secrets
from pathlib import Path
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from app.database import init_db, get_dashboard_metrics, get_all_incidents, get_malicious_blocklist
from app.canary import generate_canary_id, inject_canary_links, record_event
from app.llm_engine import generate_deceptive_response
from app.fingerprint import analyze_client_fingerprint
from app.threat_intel import (
    get_real_attacker_ip, calculate_threat_score, dispatch_webhook_alert,
    is_ip_blocked, check_auth_lockout, register_failed_auth, clear_failed_auth,
    check_rate_limit, sanitize_log_text, format_cef_event
)

if os.path.exists(".env"):
    with open(".env", encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ[k] = v

init_db()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
security = HTTPBasic()
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", "16384"))

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": "Internal Gateway Error"})

@app.middleware("http")
async def security_and_rate_middleware(request: Request, call_next):
    attacker_ip = get_real_attacker_ip(request)
    if request.url.path != "/health_check" and check_rate_limit(attacker_ip):
        return JSONResponse(status_code=429, content={"error": "Rate Limit Exceeded - IP Quarantined"})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    if request.url.path.startswith("/soc/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )
    return response

def verify_soc_analyst(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    client_ip = get_real_attacker_ip(request)
    if check_auth_lockout(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Locked for 15 minutes."
        )

    expected_user = os.getenv("SOC_USERNAME", "admin")
    expected_pass = os.getenv("SOC_PASSWORD", "AdHDF_Soc2026!")
    is_user_ok = secrets.compare_digest(credentials.username.encode("utf8"), expected_user.encode("utf8"))
    is_pass_ok = secrets.compare_digest(credentials.password.encode("utf8"), expected_pass.encode("utf8"))
    
    if not (is_user_ok and is_pass_ok):
        register_failed_auth(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SOC Authorization Required",
            headers={"WWW-Authenticate": "Basic"},
        )
    clear_failed_auth(client_ip)
    return credentials.username

def get_dynamic_callback_host(request: Request) -> str:
    configured = os.getenv("CALLBACK_HOST", "")
    if configured and "localhost" not in configured:
        return configured.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", "http")
    host = request.headers.get("host", "localhost:8000")
    return f"{proto}://{host}"

def classify_attack(path: str, query: str, body: str) -> str:
    combined = f"{path} {query} {body}".lower()
    if "169.254.169.254" in combined or "metadata.google" in combined or "file://" in combined or "gopher://" in combined:
        return "SSRF / Cloud Metadata Probe"
    if any(k in combined for k in ["id_rsa", ".pem", ".aws/credentials", "kube/config", "shadow"]):
        return "Credential / Key Harvesting"
    if any(k in combined for k in [";id", "|id", "$(", "`", "cmd.exe", "powershell", "/bin/sh", "/bin/bash"]):
        return "Command Injection / RCE"
    if any(k in combined for k in [".env", "config", ".git", "wp-config", ".sql", "backup"]):
        return "Sensitive File Exposure"
    if "'" in combined or "union select" in combined or "1=1" in combined or "sleep(" in combined:
        return "SQL Injection"
    if "../" in combined or "..\\" in combined or "/etc/passwd" in combined or "win.ini" in combined:
        return "Path Traversal / LFI"
    return "Directory Fuzzing / Recon"

def generate_persona_artifact(path: str, canary_traps: dict):
    p = path.lower()
    if "id_rsa" in p or p.endswith(".pem"):
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"# Internal Bastion Key - Audit Endpoint: {canary_traps['tracking_webhook']}\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "QyNTUxOQAAACB8k9LmP2xQ9vN7wR4tY1uJ6hG3fD8sA2zX5cV9bN0mQAAAApBZG1pbkBwcm\n"
            "9kLWJhc3Rpb24tMDEBAgMEBQYH\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
            "text/plain"
        )
    if ".aws/credentials" in p:
        return (
            "[default]\n"
            f"aws_access_key_id = {canary_traps['aws_access_key']}\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY99\n"
            "region = eu-central-1\n"
            f"# STS AssumeRole Callback: {canary_traps['internal_backup_url']}\n",
            "text/plain"
        )
    if p.endswith(".sql"):
        return (
            "-- PostgreSQL Enterprise Core Dump\n"
            f"-- Remote Replication Stream: {canary_traps['internal_backup_url']}\n"
            "CREATE TABLE admin_users (id SERIAL PRIMARY KEY, username VARCHAR(50), password_hash TEXT);\n"
            "INSERT INTO admin_users VALUES (1, 'sysadmin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK8i');\n",
            "application/sql"
        )
    return None, None

@app.get("/health_check")
async def health_check():
    return Response(status_code=204)

@app.get("/soc/dashboard", response_class=HTMLResponse)
async def soc_dashboard(analyst: str = Depends(verify_soc_analyst)):
    base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    html_path = Path(base_path) / "templates" / "dashboard.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.get("/soc/stats")
async def get_soc_stats(analyst: str = Depends(verify_soc_analyst)):
    return get_dashboard_metrics()

@app.get("/soc/blocklist", response_class=PlainTextResponse)
async def export_firewall_blocklist(analyst: str = Depends(verify_soc_analyst)):
    threshold = int(os.getenv("BLOCK_THRESHOLD", "75"))
    blocked = get_malicious_blocklist(min_score=threshold)
    lines = [f"# AdHDF Enterprise Blocklist (Threshold >= {threshold})"]
    for item in blocked:
        lines.append(f"{item['ip']} # Score: {item['max_risk_score']} | Last Seen: {item['last_seen']}")
    return "\n".join(lines)

@app.get("/soc/siem/cef", response_class=PlainTextResponse)
async def export_siem_cef_feed(analyst: str = Depends(verify_soc_analyst)):
    incidents = get_all_incidents()[:100]
    return "\n".join([format_cef_event(inc) for inc in incidents])

@app.get("/soc/export")
async def export_soc_report(analyst: str = Depends(verify_soc_analyst)):
    incidents = get_all_incidents()
    return JSONResponse(
        content={"framework": "AdHDF Enterprise v1.2", "exported_by": analyst, "total_incidents": len(incidents), "incidents": incidents},
        headers={"Content-Disposition": "attachment; filename=AdHDF_Enterprise_SOC_Report.json"}
    )

@app.api_route("/internal/backup/{canary_id}/{filename}", methods=["GET", "POST"])
@app.api_route("/api/v1/telemetry/{canary_id}", methods=["GET", "POST"])
async def canary_triggered(request: Request, canary_id: str, filename: str = ""):
    if not re.match(r"^cnry_[a-f0-9]{12}$", canary_id):
        return Response(status_code=404)

    headers_dict = dict(request.headers)
    attacker_ip = get_real_attacker_ip(request)
    fp = analyze_client_fingerprint(headers_dict)
    threat_info = calculate_threat_score(attacker_ip, "CRITICAL_CANARY_TRIGGERED", fp["confidence"])

    entry = record_event(
        event_type="CRITICAL_CANARY_TRIGGERED",
        ip=attacker_ip,
        path=sanitize_log_text(request.url.path, 250),
        headers=headers_dict,
        payload="",
        canary_id=canary_id,
        ai_output="403 Forbidden - Canary Beacon Logged & IP Permanently Quarantined",
        fingerprint=fp,
        threat_info=threat_info
    )
    await dispatch_webhook_alert(entry)
    return Response(content='{"error": "Access Denied: Incident Logged"}', media_type="application/json", status_code=403)

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def deception_catch_all(request: Request, full_path: str):
    attacker_ip = get_real_attacker_ip(request)
    
    if is_ip_blocked(attacker_ip):
        return Response(content='{"error": "IP Quarantined by Active Defense"}', media_type="application/json", status_code=403)

    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_PAYLOAD_BYTES:
        return Response(content='{"error": "Payload Too Large"}', media_type="application/json", status_code=413)

    body_bytes = await request.body()
    if len(body_bytes) > MAX_PAYLOAD_BYTES:
        return Response(content='{"error": "Payload Too Large"}', media_type="application/json", status_code=413)

    body_str = sanitize_log_text(body_bytes.decode("utf-8", errors="ignore"), 1500)
    query_str = sanitize_log_text(str(request.query_params), 500)
    path_str = sanitize_log_text(f"/{full_path}", 250)
    headers_dict = dict(request.headers)

    attack_type = classify_attack(path_str, query_str, body_str)
    fp = analyze_client_fingerprint(headers_dict)
    threat_info = calculate_threat_score(attacker_ip, attack_type, fp["confidence"])
    
    canary_id = generate_canary_id()
    dynamic_host = get_dynamic_callback_host(request)
    canary_traps = inject_canary_links(dynamic_host, canary_id)

    artifact_content, artifact_mime = generate_persona_artifact(path_str, canary_traps)
    if artifact_content:
        ai_response = artifact_content
        media_type = artifact_mime
    else:
        ai_response = await generate_deceptive_response(
            path=path_str,
            method=request.method,
            query=query_str,
            body=body_str,
            attack_type=attack_type,
            canary_traps=canary_traps
        )
        media_type = "text/plain" if ".env" in path_str else "application/json"

    entry = record_event(
        event_type=attack_type,
        ip=attacker_ip,
        path=path_str,
        headers=headers_dict,
        payload=body_str,
        canary_id=canary_id,
        ai_output=ai_response,
        fingerprint=fp,
        threat_info=threat_info
    )

    threshold = int(os.getenv("BLOCK_THRESHOLD", "75"))
    if threat_info["risk_score"] >= threshold:
        await dispatch_webhook_alert(entry)

    return Response(content=ai_response, media_type=media_type, status_code=200)
