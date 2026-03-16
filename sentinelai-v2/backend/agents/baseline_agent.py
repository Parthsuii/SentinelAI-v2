"""
SentinelAI v3.0 — Baseline Anomaly Agent (Tier 1)
Model: Phi-3.5-mini INT4
Compares site behavior to personal baseline and flags deviations.
"""
def check_baseline(domain: str, current_hooks: list) -> dict:
    from backend.main import ephemeral
    if not domain:
        return {"agent": "baseline-agent", "score": 0, "anomalous": False}
        
    baseline = ephemeral.get_session(f"baseline:{domain}")
    hooks_fired = [e.get("hook") for e in current_hooks]
    
    if not baseline:
        # Unknown domain - slight suspicion if active hooks present
        return {"agent": "baseline-agent", "score": 30 if hooks_fired else 0, "anomalous": False}
        
    expected = set(baseline.get("hooks_fired", []))
    unexpected = set(hooks_fired) - expected
    
    score = min(100, len(unexpected) * 25)
    
    threats = []
    if unexpected:
        threats.append({"type": "baseline-anomaly", "detail": f"Unexpected hooks fired: {', '.join(unexpected)}"})
        
    return {
        "agent": "baseline-agent",
        "score": score,
        "anomalous": score >= 50,
        "unexpected_hooks": list(unexpected),
        "threats": threats
    }

def update_baseline(domain: str, hook: str):
    from backend.main import ephemeral
    if not domain: return
    baseline = ephemeral.get_session(f"baseline:{domain}") or {"hooks_fired": [], "visits": 0}
    if hook not in baseline["hooks_fired"]:
        baseline["hooks_fired"].append(hook)
    baseline["visits"] += 1
    ephemeral.set_session(f"baseline:{domain}", baseline)
