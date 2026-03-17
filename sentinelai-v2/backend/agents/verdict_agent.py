"""
SentinelAI v2.0 — Verdict Agent
Model: LFM2.5-2B-Thinking via Ollama
Combines all agent outputs, computes final risk score, generates explanation, decides block/warn/allow
"""

from urllib.parse import urlparse


MODEL_NAME = "Qwen2.5-1.5B-Instruct"

AGENT_WEIGHTS = {
    "url-agent": 0.10,
    "content-agent": 0.10,
    "runtime-agent": 0.15,
    "visual-agent": 0.10,
    "tracker-agent": 0.10,
    "exfil-agent": 0.075,
    "baseline-agent": 0.075,
    "campaign-agent": 0.10
}

LEVEL_THRESHOLDS = {"safe": 18, "low": 40, "medium": 75, "high": 80}
SEVERE_THREAT_FLOORS = {
    "sensitive-third-party-exfil": 85,
    "sensitive-exfil": 75,
    "credential-exfil": 65,
    "redirect-jump": 70,       # v3
    "clickjacking-ui": 75,     # v3
    "credential-access": 60,   # v3
    "session-theft": 70,
    "network-tracker-critical": 65,
    "network-tracker-high": 45,
    "combined-tracking": 55,
    "jurisdiction-risk": 25
}

HIGH_CONFIDENCE_THREAT_MARKERS = (
    "credential",
    "session-theft",
    "sensitive-exfil",
    "third-party-exfil",
    "redirect-jump",
    "clickjacking-ui",
    "brand-impersonation",
    "homoglyph",
    "malware",
)

MEDIUM_CONFIDENCE_THREAT_MARKERS = (
    "phishing",
    "cross-origin-form",
    "overlay",
    "eval",
    "iframe",
    "canvas-fingerprint",
    "webgl-fingerprint",
    "combined-tracking",
)


def _threat_type(threat: dict) -> str:
    return str(threat.get("type", "") or "").lower()


def _is_high_confidence_threat(threat: dict) -> bool:
    t = _threat_type(threat)
    return any(marker in t for marker in HIGH_CONFIDENCE_THREAT_MARKERS)


def _is_medium_confidence_threat(threat: dict) -> bool:
    t = _threat_type(threat)
    return any(marker in t for marker in MEDIUM_CONFIDENCE_THREAT_MARKERS)


def _has_only_data_sharing(result: dict) -> bool:
    threats = result.get("threats", []) or []
    data_sharing = result.get("data_sharing", []) or []
    return not threats and bool(data_sharing)

def compute_verdict(agent_results: dict) -> dict:
    """Aggregate all agent scores using v3 Ensemble Risk Matrix."""
    composite_score = 0.0
    all_threats = []
    breakdown = {}
    data_sharing = []
    domain_locations = {}
    blocking_tips = []
    active_agents = 0

    for agent_name, weight in AGENT_WEIGHTS.items():
        result = agent_results.get(agent_name) or {}
        raw_score = result.get("score", 0)
        if _has_only_data_sharing(result):
            raw_score = 0
        threat_list = result.get("threats", [])
        threat_count = len(threat_list)
        if raw_score >= 10 or threat_count > 0:
            active_agents += 1

        reliability = 1.0
        if raw_score > 0:
            if any(_is_high_confidence_threat(t) for t in threat_list):
                reliability = 1.0
            elif any(_is_medium_confidence_threat(t) for t in threat_list):
                reliability = 0.85
            elif threat_count > 0:
                reliability = 0.75
            else:
                reliability = 0.65

        weighted = raw_score * weight * reliability
        composite_score += weighted

        breakdown[agent_name] = {
            "raw_score": raw_score,
            "weight": weight,
            "weighted_score": round(weighted, 1),
            "threat_count": threat_count
        }

        for threat in threat_list:
            all_threats.append({**threat, "source": agent_name})
        for share in result.get("data_sharing", []):
            if share not in data_sharing:
                data_sharing.append({**share, "source": agent_name})
        for tip in result.get("blocking_tips", []):
            if tip not in blocking_tips:
                blocking_tips.append({**tip, "source": agent_name})
                
        dl = result.get("domain_locations", {})
        if isinstance(dl, dict):
            domain_locations.update(dl)
        elif isinstance(dl, list):
            for location in dl:
                domain = (location.get("domain") or "").lower()
                if domain:
                    domain_locations[domain] = location.get("location") or {}

    monitor_result = agent_results.get("monitor-analysis") or {}
    monitor_locations = monitor_result.get("domain_locations", {})
    if isinstance(monitor_locations, dict):
        domain_locations.update(monitor_locations)

    for share in data_sharing:
        destination = share.get("destination", "")
        try:
            hostname = (urlparse(destination).hostname or destination).lower()
        except Exception:
            hostname = destination.lower()
        if hostname in domain_locations:
            share["location"] = domain_locations[hostname]

    # Floor logic: If any agent identifies a critical threat, composite score cannot be below floor
    threat_floor = 0
    for threat in all_threats:
        threat_floor = max(threat_floor, SEVERE_THREAT_FLOORS.get(threat.get("type", ""), 0))

    high_confidence_threats = [t for t in all_threats if _is_high_confidence_threat(t)]
    medium_confidence_threats = [t for t in all_threats if _is_medium_confidence_threat(t)]

    if not high_confidence_threats:
        if active_agents <= 1:
            composite_score *= 0.72
        elif active_agents == 2:
            composite_score *= 0.82
        else:
            composite_score *= 0.9

        # Keep weak multi-signal pages in a moderate range unless a hard floor says otherwise.
        if threat_floor < 60:
            soft_cap = 50 if active_agents <= 1 else 58 if active_agents == 2 else 65
            if not medium_confidence_threats:
                soft_cap -= 5
            composite_score = min(composite_score, soft_cap)

        # If two or more agents mildly agree, surface that as a low warning
        # instead of silently collapsing it into "safe".
        if threat_floor == 0 and active_agents >= 2:
            has_multi_signal_evidence = bool(medium_confidence_threats) or composite_score >= 10
            if has_multi_signal_evidence and composite_score < LEVEL_THRESHOLDS["safe"]:
                composite_score = float(LEVEL_THRESHOLDS["safe"])

    if threat_floor:
        composite_score = max(composite_score, threat_floor)

    composite_score = min(round(composite_score, 1), 100)

    # Determine level
    if composite_score < LEVEL_THRESHOLDS["safe"]:
        level = "safe"
    elif composite_score < LEVEL_THRESHOLDS["low"]:
        level = "low"
    elif composite_score < LEVEL_THRESHOLDS["medium"]:
        level = "medium"
    elif composite_score < LEVEL_THRESHOLDS["high"]:
        level = "high"
    else:
        level = "critical"

    if high_confidence_threats and threat_floor >= 65 and level == "medium":
        level = "high"

    should_block = composite_score >= 80

    # Action
    if should_block:
        action = "block"
    elif level in ("medium", "high"):
        action = "warn"
    else:
        action = "allow"

    recommendations = {
        "safe": "This site appears safe. No threats detected.",
        "low": "Minor concerns detected. Proceed with normal caution.",
        "medium": "Moderate risk detected. Avoid entering sensitive data.",
        "high": "High risk! Do not enter credentials or personal information.",
        "critical": "CRITICAL THREAT! This site is likely malicious. Leave immediately."
    }

    if data_sharing:
        cross_origin_shares = [d for d in data_sharing if d.get("cross_origin")]
        if cross_origin_shares:
            destinations = ", ".join(sorted(list({d.get("destination", "") for d in cross_origin_shares if d.get("destination")})))
            recommendations[level] = f"{recommendations[level]} Data is being sent to: {destinations}."
            
        # Add a hint about blocking
        if blocking_tips:
            recommendations[level] = f"{recommendations[level]} See Data Sharing section for blocking tips."

    return {
        "agent": "verdict-agent",
        "model": MODEL_NAME,
        "composite_score": composite_score,
        "level": level,
        "action": action,
        "should_block": should_block,
        "recommendation": recommendations[level],
        "all_threats": all_threats,
        "agent_breakdown": breakdown,
        "data_sharing": data_sharing,
        "blocking_tips": blocking_tips
    }


async def compute_verdict_llm(agent_results: dict, url: str = "") -> dict:
    """Enhanced verdict with LFM2.5-2B-Thinking explanation."""
    verdict = compute_verdict(agent_results)

    threat_summary = "\n".join(
        f"- [{t['source']}] {t['type']}: {t['detail']}"
        for t in verdict["all_threats"][:10]
    )

    prompt = f"""You are a cybersecurity verdict agent. Based on the analysis below, provide a final security assessment.

URL: {url}
Composite Score: {verdict['composite_score']}/100
Level: {verdict['level']}
Action: {verdict['action']}

Top threats:
{threat_summary}

Agent scores: {verdict['agent_breakdown']}

Provide JSON with:
- "explanation": 2-3 sentence explanation for a non-technical user
- "technical_summary": brief technical summary
- "confidence": 0-100

Respond ONLY with valid JSON."""

    try:
        from backend.ollama_engine import generate_async, is_available
        if is_available():
            verdict["llm_explanation"] = await generate_async("verdict-agent", prompt)
        else:
            verdict["llm_explanation"] = "Ollama not available"
    except Exception as e:
        verdict["llm_explanation"] = f"LLM unavailable: {str(e)}"

    return verdict
