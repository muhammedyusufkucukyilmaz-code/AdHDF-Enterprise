import hashlib

def analyze_client_fingerprint(headers: dict) -> dict:
    user_agent = headers.get("user-agent", "").lower()
    header_keys = [k.lower() for k in headers.keys()]
    
    # Başlık sırasından benzersiz bir HTTP parmak izi özeti (hash) çıkar
    header_sequence = ",".join(header_keys)
    http_fp_hash = hashlib.sha256(header_sequence.encode()).hexdigest()[:16]

    detected_tool = "Unknown / Custom Script"
    confidence = "Low"

    # 1. Bilinen araç imzaları ve başlık sıralaması analizi
    if "sqlmap" in user_agent:
        detected_tool = "SQLMap (Automated SQLi)"
        confidence = "High"
    elif "nuclei" in user_agent or "projectdiscovery" in user_agent:
        detected_tool = "Nuclei (Vulnerability Scanner)"
        confidence = "High"
    elif "fuzz faster u fool" in user_agent or "ffuf" in user_agent:
        detected_tool = "FFUF (Directory Fuzzer)"
        confidence = "High"
    elif "gobuster" in user_agent or "dirbuster" in user_agent:
        detected_tool = "Gobuster / DirBuster"
        confidence = "High"
    elif "curl" in user_agent or header_keys == ["host", "user-agent", "accept"]:
        detected_tool = "cURL (CLI Client)"
        confidence = "High"
    elif "python-requests" in user_agent or "aiohttp" in user_agent or "httpx" in user_agent:
        detected_tool = "Python Automation Script"
        confidence = "High"
    elif "sec-fetch-site" in header_keys and "accept-language" in header_keys:
        detected_tool = "Standard Web Browser"
        confidence = "Medium"
    elif "accept-encoding" in header_keys and "user-agent" in header_keys and len(header_keys) <= 4:
        # User-Agent sahtelenmiş olsa bile minimal başlık diziliminden CLI/Bot tespiti
        detected_tool = "Spoofed CLI / Automated Scanner"
        confidence = "Medium"

    return {
        "detected_tool": detected_tool,
        "confidence": confidence,
        "http_fp_hash": http_fp_hash,
        "header_sequence": header_sequence
    }
