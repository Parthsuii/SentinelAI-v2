"""
SentinelAI v2.0 — Tracker Agent
Analyzes localStorage/sessionStorage and canvas/WebGL fingerprinting hooks.
Detects persistent cross-site tracking.
"""


KNOWN_TRACKERS = {
    '_ga', '_gid', '_gat', '_fbp', '_fbc', '__utma', '__utmb', '__utmc', '__utmz',
    'mp_', 'ajs_', '_hjid', '_hjSession', 'intercom-id', 'amplitude_id',
    '_clck', '_clsk', 'muxData', 'fs_uid', '_dd_s'
}


def analyze_heuristic(events: list) -> dict:
    """Analyze storage and canvas events for tracking behavior."""
    threats = []
    score = 0

    storage_events = [e for e in events if e.get("hook") == "storage"]
    canvas_events = [e for e in events if e.get("hook") == "canvas"]

    # Storage tracking analysis
    tracking_keys = set()
    for event in storage_events:
        data = event.get("data", {})
        key = data.get("key", "")
        action = data.get("action", "")

        if data.get("isTrackingId"):
            tracking_keys.add(key)

        # Check against known tracker patterns
        for tracker in KNOWN_TRACKERS:
            if key.startswith(tracker) or key == tracker:
                tracking_keys.add(key)
                break

        # Base64 values in storage (fingerprint IDs)
        if action == "set" and data.get("isBase64"):
            score += 5
            threats.append({"type": "encoded-tracker", "detail": f"Encoded tracking ID stored in {data.get('storage', 'storage')}: {key}"})

    if tracking_keys:
        score += min(len(tracking_keys) * 5, 30)
        threats.append({
            "type": "persistent-tracking",
            "detail": f"{len(tracking_keys)} tracking key(s): {', '.join(list(tracking_keys)[:5])}"
        })

    # Canvas fingerprinting
    canvas_data_url = [e for e in canvas_events if e.get("data", {}).get("action") == "toDataURL"]
    webgl_queries = [e for e in canvas_events if e.get("data", {}).get("action") == "webgl-getParameter"]

    if canvas_data_url:
        score += 15
        threats.append({"type": "canvas-fingerprint", "detail": f"{len(canvas_data_url)} canvas fingerprint extraction(s)"})

    if webgl_queries:
        score += 10
        threats.append({"type": "webgl-fingerprint", "detail": f"WebGL renderer/vendor queried ({len(webgl_queries)} times)"})

    # Combined fingerprinting (canvas + storage = high confidence tracking)
    if canvas_data_url and tracking_keys:
        score += 15
        threats.append({"type": "combined-tracking", "detail": "Canvas fingerprinting + persistent storage tracking"})

    return {
        "agent": "tracker-agent",
        "score": min(score, 100),
        "threats": threats,
        "tracking_keys": list(tracking_keys)
    }
