import uuid
from datetime import datetime, timezone
from app.database import insert_incident

def generate_canary_id() -> str:
    return f"cnry_{uuid.uuid4().hex[:12]}"

def inject_canary_links(base_host: str, canary_id: str) -> dict:
    clean_host = base_host.rstrip("/")
    return {
        "internal_backup_url": f"{clean_host}/internal/backup/{canary_id}/prod_dump.sql",
        "tracking_webhook": f"{clean_host}/api/v1/telemetry/{canary_id}",
        "aws_access_key": f"AKIA{canary_id.replace('cnry_', '').upper()}99X"
    }

def record_event(event_type: str, ip: str, path: str, headers: dict, payload: str, canary_id: str, ai_output: str, fingerprint: dict, threat_info: dict) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    tool = fingerprint.get("tool", "Unknown")
    score = int(threat_info.get("risk_score", 0))
    insert_incident(
        timestamp=ts,
        event_type=event_type,
        ip=ip,
        path=path,
        tool_detected=tool,
        risk_score=score,
        canary_id=canary_id,
        payload=payload,
        ai_output=ai_output
    )
    return {
        "timestamp": ts,
        "event_type": event_type,
        "ip": ip,
        "path": path,
        "tool_detected": tool,
        "risk_score": score,
        "canary_id": canary_id
    }
