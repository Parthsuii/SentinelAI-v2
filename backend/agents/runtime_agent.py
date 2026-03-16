"""
SentinelAI v2.0 — Runtime Agent
Model: Phi-4-mini-reasoning (shared instance with Content Agent)
Analyzes real-time hook events: fetch, WebSocket, DOM mutations, cookie access, eval
"""

MODEL_NAME = "phi4-mini"


def analyze_heuristic(events: list, hostname: str = "") -> dict:
    """Heuristic runtime event analysis."""
    threats = []
    score = 0

    if not events:
        return {"agent": "runtime-agent", "model": MODEL_NAME, "score": 0, "threats": []}

    hook_counts = {}
    for e in events:
        hook = e.get("hook", "unknown")
        hook_counts[hook] = hook_counts.get(hook, 0) + 1

    # Excessive network calls
    net_calls = sum(hook_counts.get(h, 0) for h in ['fetch', 'xhr', 'beacon'])
    if net_calls > 20:
        score += 15
        threats.append({"type": "excessive-network", "detail": f"{net_calls} outbound network calls"})

    # Eval usage
    if hook_counts.get('eval', 0) > 0:
        score += 20
        threats.append({"type": "eval-usage", "detail": f"{hook_counts['eval']} eval/Function calls"})
        for e in events:
            if e.get("hook") == "eval" and e.get("data", {}).get("hasBase64"):
                score += 15
                threats.append({"type": "eval-base64", "detail": "Base64 decoding in eval (obfuscated malware)"})

    # DOM injection
    for e in events:
        if e.get("hook") == "mutation":
            reason = e.get("data", {}).get("reason", "")
            if reason == "overlay-injection":
                score += 25
                threats.append({"type": "overlay-injection", "detail": "Full-screen overlay (clickjacking)"})
            elif reason == "iframe-injection":
                score += 20
                threats.append({"type": "iframe-injection", "detail": "Hidden iframe injected"})
            elif reason == "form-injection":
                score += 20
                threats.append({"type": "form-injection", "detail": "Form dynamically injected"})

    # Cookie theft
    cookie_reads = [e for e in events if e.get("hook") == "cookie" and e.get("data", {}).get("action") == "read"]
    session_reads = [e for e in cookie_reads if e.get("data", {}).get("hasSessionId")]
    if session_reads:
        score += 20
        threats.append({"type": "session-theft", "detail": f"Session cookies accessed {len(session_reads)} times"})

    # Permission abuse
    perm_events = [e for e in events if e.get("hook") == "permission"]
    for pe in perm_events:
        action = pe.get("data", {}).get("action", "")
        if action == "getUserMedia":
            score += 20
            media = []
            if pe.get("data", {}).get("video"):
                media.append("camera")
            if pe.get("data", {}).get("audio"):
                media.append("microphone")
            threats.append({"type": "media-access", "detail": f"Page requested {'+'.join(media)} access"})
        elif action == "geolocation":
            score += 10
            threats.append({"type": "geolocation-access", "detail": "Page requested geolocation"})

    # WebSocket C2 channels
    ws_connects = [e for e in events if e.get("hook") == "websocket" and e.get("data", {}).get("action") == "connect"]
    if len(ws_connects) > 3:
        score += 15
        threats.append({"type": "c2-channel", "detail": f"{len(ws_connects)} WebSocket connections (possible C2)"})

    # Canvas fingerprinting
    if hook_counts.get('canvas', 0) > 0:
        score += 10
        threats.append({"type": "fingerprinting", "detail": "Canvas/WebGL fingerprinting detected"})

    # Clipboard access
    clip_reads = [e for e in events if e.get("hook") == "clipboard" and e.get("data", {}).get("action") == "read"]
    if clip_reads:
        score += 15
        threats.append({"type": "clipboard-read", "detail": "Page read clipboard contents"})

    return {
        "agent": "runtime-agent",
        "model": MODEL_NAME,
        "score": min(score, 100),
        "threats": threats,
        "hook_counts": hook_counts
    }


async def analyze_llm(events: list, hostname: str = "") -> dict:
    """Enhanced analysis using Phi-3.5-mini-instruct via AirLLM (shared instance)."""
    heuristic = analyze_heuristic(events, hostname)

    event_summary = f"Hook counts: {heuristic.get('hook_counts', {})}\n"
    event_summary += f"Hostname: {hostname}\n"
    event_summary += f"Sample events: {events[:5]}"

    prompt = f"""You are a runtime behavior analysis agent. Analyze these browser runtime events for threats.

{event_summary}

Heuristic findings: {heuristic['threats']}

Provide JSON with:
- "behavior_assessment": brief analysis of what the page is doing
- "is_malicious": true/false
- "confidence": 0-100

Respond ONLY with valid JSON."""

    try:
        from backend.ollama_engine import generate_async, is_available
        if is_available():
            heuristic["llm_analysis"] = await generate_async("runtime-agent", prompt)
        else:
            heuristic["llm_analysis"] = "AirLLM not installed"
    except Exception as e:
        heuristic["llm_analysis"] = f"LLM unavailable: {str(e)}"

    return heuristic
