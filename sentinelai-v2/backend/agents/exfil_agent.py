"""
SentinelAI v2.0 — Exfiltration Agent
Model: Qwen2.5-1.5B-Instruct via Ollama
Purpose: decode obfuscated payloads, analyze Base64 credentials, inspect hidden form fields, sendBeacon exfiltration
"""

import re
import base64
from urllib.parse import urlparse

MODEL_NAME = "Qwen2.5-1.5B-Instruct"

SENSITIVE_PATTERNS = [
    (r"password", "password field"),
    (r"passwd", "password field"),
    (r"credit.?card", "credit card"),
    (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "credit card number"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email address"),
    (r"bearer\s+[a-zA-Z0-9\-._~+/]+=*", "bearer token"),
    (r"api[_-]?key", "API key"),
]


def _is_base64(s: str) -> bool:
    if not s or len(s) < 20:
        return False
    return bool(re.match(r'^[A-Za-z0-9+/=]{20,}$', s.strip()))


def _try_decode_base64(s: str) -> str | None:
    try:
        decoded = base64.b64decode(s.strip()).decode('utf-8', errors='replace')
        return decoded
    except Exception:
        return None


def _is_hex_encoded(s: str) -> bool:
    if not s or len(s) < 20:
        return False
    return bool(re.match(r'^[0-9a-fA-F]{20,}$', s.strip()))


def _contains_sensitive(text: str) -> list:
    found = []
    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(label)
    return found


def _extract_destination(data: dict) -> str:
    return data.get("destination") or data.get("url") or ""


def _normalize_origin(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return ""
    return value


def analyze_heuristic(events: list) -> dict:
    """Analyze outbound events for data exfiltration."""
    threats = []
    score = 0
    data_sharing = []

    network_events = [e for e in events if e.get("hook") in ("fetch", "xhr", "beacon", "websocket")]

    for event in network_events:
        data = event.get("data", {})
        body = data.get("bodyPreview") or data.get("dataPreview") or ""
        url = _extract_destination(data)
        event_origin = _normalize_origin(event.get("origin", ""))
        destination_origin = _normalize_origin(url)
        sensitive = _contains_sensitive(body) if body else []
        shared_record = None

        # Base64 payload
        if _is_base64(body):
            decoded = _try_decode_base64(body)
            score += 20
            threats.append({"type": "base64-exfil", "detail": f"Base64 data sent via {event['hook']}"})
            if decoded:
                decoded_sensitive = _contains_sensitive(decoded)
                if decoded_sensitive:
                    score += 25
                    threats.append({"type": "sensitive-exfil", "detail": f"Decoded payload contains: {', '.join(decoded_sensitive)}"})
                    sensitive = sorted(set(sensitive + decoded_sensitive))

        # Hex payload
        if _is_hex_encoded(body):
            score += 15
            threats.append({"type": "hex-exfil", "detail": f"Hex-encoded data via {event['hook']}"})

        # Credentials in body
        if sensitive:
            score += 20
            threats.append({"type": "credential-exfil", "detail": f"Possible {', '.join(sensitive)} in {event['hook']} body"})

        # Long URL exfiltration
        if len(url) > 500:
            encoded_count = url.count('%')
            if encoded_count > 10:
                score += 15
                threats.append({"type": "url-exfil", "detail": "Data smuggled via long encoded URL"})

        # Cross-origin data send
        if destination_origin and event_origin and destination_origin != event_origin:
            shared_record = {
                "destination": destination_origin,
                "via": event.get("hook", "network"),
                "data_types": sensitive,
                "has_payload": bool(body),
                "cross_origin": True
            }
            if body:
                score += 10
                threats.append({"type": "third-party-exfil", "detail": f"Data sent to {destination_origin}"})
            if sensitive:
                score += 25
                threats.append({
                    "type": "sensitive-third-party-exfil",
                    "detail": f"Sensitive data ({', '.join(sensitive)}) sent to {destination_origin}"
                })
        elif destination_origin:
            shared_record = {
                "destination": destination_origin,
                "via": event.get("hook", "network"),
                "data_types": sensitive,
                "has_payload": bool(body),
                "cross_origin": False
            }

        if shared_record and shared_record["has_payload"]:
            data_sharing.append(shared_record)

    deduped_data_sharing = []
    seen = set()
    for entry in data_sharing:
        key = (
            entry.get("destination", ""),
            entry.get("via", ""),
            tuple(entry.get("data_types", [])),
            entry.get("cross_origin", False)
        )
        if key in seen:
            continue
        seen.add(key)
        deduped_data_sharing.append(entry)

    return {
        "agent": "exfil-agent",
        "model": MODEL_NAME,
        "score": min(score, 100),
        "threats": threats,
        "data_sharing": deduped_data_sharing
    }


async def analyze_llm(events: list) -> dict:
    """Enhanced analysis using Qwen2.5-1.5B-Instruct via Ollama."""
    heuristic = analyze_heuristic(events)

    payloads = []
    for e in events:
        if e.get("hook") in ("fetch", "xhr", "beacon"):
            body = e.get("data", {}).get("bodyPreview", "")
            if body:
                payloads.append(body[:200])

    if not payloads:
        return heuristic

    prompt = f"""You are a data exfiltration analysis agent. Analyze these outbound payloads for credential theft or data exfiltration.

Payloads:
{chr(10).join(payloads[:5])}

Heuristic findings: {heuristic['threats']}

Provide JSON with:
- "exfil_assessment": brief analysis
- "is_exfiltrating": true/false
- "data_types_at_risk": list of data types being sent
- "confidence": 0-100

Respond ONLY with valid JSON."""

    try:
        from backend.ollama_engine import generate_async, is_available
        if is_available():
            heuristic["llm_analysis"] = await generate_async("exfil-agent", prompt)
        else:
            heuristic["llm_analysis"] = "AirLLM not installed"
    except Exception as e:
        heuristic["llm_analysis"] = f"LLM unavailable: {str(e)}"

    return heuristic
