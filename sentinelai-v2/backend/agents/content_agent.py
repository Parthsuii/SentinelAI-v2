"""
SentinelAI v2.0 — Content Agent
Model: Phi-4-mini-reasoning via Ollama
Analyzes: DOM structure, script sources, iframe origins, obfuscated JS, login form destinations
"""

import re

MODEL_NAME = "phi4-mini"

PHISHING_PATTERNS = [
    (r"your account (?:has been|was) (?:suspended|locked|compromised)", 30, "Account suspension scare"),
    (r"verify your (?:identity|account|email)", 20, "Identity verification prompt"),
    (r"unusual (?:activity|sign.?in|login)", 25, "Unusual activity warning"),
    (r"update your (?:payment|billing|credit card)", 30, "Payment update request"),
    (r"confirm your (?:password|credentials)", 35, "Credential confirmation request"),
    (r"click (?:here|below) (?:to|within) (?:\d+\s*hours?)", 25, "Urgency pressure tactic"),
    (r"your (?:package|shipment|order) (?:could not|cannot) be delivered", 20, "Delivery scam"),
    (r"enter your (?:ssn|social security|tax id)", 40, "SSN phishing"),
    (r"we detected (?:a |an )?(?:unauthorized|suspicious)", 25, "Fake security alert"),
]


def analyze_heuristic(signals: dict) -> dict:
    """Heuristic content analysis."""
    threats = []
    score = 0

    body_text = signals.get("bodyTextPreview", "")
    hostname = signals.get("hostname", "")
    title = signals.get("title", "")
    protocol = signals.get("protocol", "https:")

    # Phishing text patterns
    for pattern, severity, label in PHISHING_PATTERNS:
        if re.search(pattern, body_text, re.IGNORECASE):
            score += severity
            threats.append({"type": "phishing-text", "detail": label})

    # Form analysis
    for form in signals.get("forms", []):
        if form.get("hasPassword"):
            if protocol == "http:":
                score += 30
                threats.append({"type": "insecure-login", "detail": "Password form on HTTP page"})
            if form.get("hasPassword") and form.get("hasEmail"):
                score += 10
                threats.append({"type": "credential-form", "detail": "Email + password form detected"})

    # Brand mismatch
    brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix']
    for brand in brands:
        if brand in title.lower() and brand not in hostname.lower():
            score += 20
            threats.append({"type": "brand-title-mismatch", "detail": f'Title mentions "{brand}" but domain doesn\'t match'})
            break

    # Excessive inline scripts
    if signals.get("inlineScriptCount", 0) > 10:
        score += 10
        threats.append({"type": "excessive-scripts", "detail": f"{signals['inlineScriptCount']} inline scripts"})

    return {
        "agent": "content-agent",
        "model": MODEL_NAME,
        "score": min(score, 100),
        "threats": threats
    }


async def analyze_llm(signals: dict) -> dict:
    """Enhanced analysis using Phi-3.5-mini-instruct via AirLLM."""
    heuristic = analyze_heuristic(signals)

    page_summary = f"""URL: {signals.get('url', '?')}
Title: {signals.get('title', '?')}
Forms: {len(signals.get('forms', []))} ({', '.join('password' for f in signals.get('forms', []) if f.get('hasPassword'))})
Scripts: {signals.get('scriptCount', 0)} total, {signals.get('inlineScriptCount', 0)} inline
External links: {signals.get('externalLinkCount', 0)}
Body preview: {signals.get('bodyTextPreview', '')[:500]}"""

    prompt = f"""You are a cybersecurity content analysis agent. Analyze this page for phishing/scam indicators.

{page_summary}

Heuristic findings: {heuristic['threats']}

Provide JSON with:
- "risk_assessment": brief analysis
- "is_phishing": true/false
- "confidence": 0-100
- "additional_threats": any missed threats

Respond ONLY with valid JSON."""

    try:
        from backend.ollama_engine import generate_async, is_available
        if is_available():
            heuristic["llm_analysis"] = await generate_async("content-agent", prompt)
        else:
            heuristic["llm_analysis"] = "AirLLM not installed"
    except Exception as e:
        heuristic["llm_analysis"] = f"LLM unavailable: {str(e)}"

    return heuristic
