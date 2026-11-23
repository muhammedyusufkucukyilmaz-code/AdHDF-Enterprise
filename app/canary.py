import uuid
from datetime import datetime
from app.database import insert_incident

def generate_canary_id() -> str:
    return f"cnry_{uuid.uuid4().hex[:12]}"

def inject_canary_links(base_url: str, canary_id: str) -> dict:
    return {
        "internal_backup_url": f"{base_url}/internal/backup/{canary_id}/dump.sql",
        "aws_access_key": f"AKIA{uuid.uuid4().hex[:16].upper()}",
        "tracking_webhook": f"{base_url}/api/v1/telemetry/{canary_id}"
    }

def record_event(event_type: str, ip: str, path: str, headers: dict, payload: str, canary_id: str, ai_output: str, fingerprint: dict, threat_info: dict) -> dict:
    entry = {
        "id": uuid.uuid4().hex[:8],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        "severity": threat_info["severity"],
        "risk_score": threat_info["risk_score"],
        "total_hits_from_ip": threat_info["total_hits_from_ip"],
        "canary_id": canary_id,
        "attacker_ip": ip,
        "target_path": path,
        "detected_tool": fingerprint["detected_tool"],
        "confidence": fingerprint["confidence"],
        "http_fp_hash": fingerprint["http_fp_hash"],
        "header_sequence": fingerprint["header_sequence"],
        "user_agent": headers.get("user-agent", "unknown"),
        "payload": payload if payload else "(Empty Body)",
        "served_response": ai_output
    }
    
    insert_incident(entry)
    print(f"\n[{threat_info['severity']} | SCORE:{threat_info['risk_score']}] {event_type} | Tool: {fingerprint['detected_tool']} | IP: {ip} | Canary: {canary_id}")
    return entry
