"""
SentinelAI v2.0 — Verdict Agent
Model: LFM2.5-2B-Thinking via Ollama
Combines all agent outputs, computes final risk score, generates explanation, decides block/warn/allow
"""


MODEL_NAME = "Qwen2.5-1.5B-Instruct"

AGENT_WEIGHTS = {
    "url-agent": 0.20,
    "content-agent": 0.15,
    "runtime-agent": 0.30,
    "exfil-agent": 0.10,
    "visual-agent": 0.05,
    "baseline-agent": 0.20
}

LEVEL_THRESHOLDS = {"safe": 15, "low": 30, "medium": 55, "high": 80}


def compute_verdict(agent_results: dict) -> dict:
    """Aggregate all agent scores using weighted risk matrix."""
    composite_score = 0.0
    all_threats = []
    breakdown = {}

    for agent_name, weight in AGENT_WEIGHTS.items():
        result = agent_results.get(agent_name, {})
        raw_score = result.get("score", 0)
        weighted = raw_score * weight
        composite_score += weighted

        breakdown[agent_name] = {
            "raw_score": raw_score,
            "weight": weight,
            "weighted_score": round(weighted, 1),
            "threat_count": len(result.get("threats", []))
        }

        for threat in result.get("threats", []):
            all_threats.append({**threat, "source": agent_name})

    # Add campaign bonus/penalty (not directly in weights, acts as modifier)
    campaign_result = agent_results.get("campaign-agent", {})
    if campaign_result and campaign_result.get("campaign_detected"):
        composite_score += 25
        for threat in campaign_result.get("threats", []):
            all_threats.append({**threat, "source": "campaign-agent"})

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

    # Action
    if level in ("critical", "high"):
        action = "block"
    elif level == "medium":
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

    return {
        "agent": "verdict-agent",
        "model": MODEL_NAME,
        "composite_score": composite_score,
        "level": level,
        "action": action,
        "recommendation": recommendations[level],
        "all_threats": all_threats,
        "agent_breakdown": breakdown
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
        from backend.airllm_engine import generate_async, is_available
        if is_available():
            verdict["llm_explanation"] = await generate_async("verdict-agent", prompt)
        else:
            verdict["llm_explanation"] = "AirLLM not available"
    except Exception as e:
        verdict["llm_explanation"] = f"LLM unavailable: {str(e)}"

    return verdict
