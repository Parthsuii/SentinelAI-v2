"""
SentinelAI v2.0 — URL + Intel Agent
Model: SmolLM2-1.7B-Instruct via Ollama
Tasks: URL entropy, homoglyph detection, typosquatting, TLD trust, threat feed queries
"""

import re
import math

import os
import httpx
from typing import Optional

MODEL_NAME = "smollm2:1.7b"

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.work', '.date', '.racing', '.win', '.bid', '.stream', '.click',
    '.link', '.loan', '.trade', '.cricket', '.science', '.party'
}

HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
    'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'ɡ': 'g', 'ɩ': 'l',
    '0': 'o', '1': 'l'
}

BRAND_DOMAINS = [
    'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'paypal.com', 'netflix.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'chase.com', 'bankofamerica.com',
    'wellsfargo.com', 'dropbox.com', 'outlook.com', 'icloud.com'
]


def _url_entropy(url: str) -> float:
    """Calculate Shannon entropy of a URL string."""
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    length = len(url)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _count_homoglyphs(hostname: str) -> int:
    return sum(1 for c in hostname if c in HOMOGLYPHS)


def _check_brand_impersonation(hostname: str) -> Optional[str]:
    for brand in BRAND_DOMAINS:
        brand_name = brand.split('.')[0]
        if brand_name in hostname and not hostname.endswith(brand):
            return brand
    return None


def analyze_heuristic(url: str) -> dict:
    """Run heuristic URL analysis (no LLM needed)."""
    threats = []
    score = 0

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        # TLD check
        tld = '.' + hostname.split('.')[-1] if '.' in hostname else ''
        if tld in SUSPICIOUS_TLDS:
            score += 20
            threats.append({"type": "suspicious-tld", "detail": f"TLD {tld} is commonly used in phishing"})

        # Homoglyphs
        hg_count = _count_homoglyphs(hostname)
        if hg_count > 0:
            score += 30
            threats.append({"type": "homoglyph", "detail": f"{hg_count} homoglyph character(s) in hostname"})

        # Brand impersonation
        brand = _check_brand_impersonation(hostname)
        if brand:
            score += 35
            threats.append({"type": "brand-impersonation", "detail": f"Possible impersonation of {brand}"})

        # IP hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            score += 15
            threats.append({"type": "ip-hostname", "detail": "URL uses IP address instead of domain"})

        # Subdomain count
        subdomain_count = hostname.count('.') - 1
        if subdomain_count > 3:
            score += 10
            threats.append({"type": "excessive-subdomains", "detail": f"{subdomain_count} subdomains"})

        # URL entropy
        entropy = _url_entropy(url)
        if entropy > 4.5:
            score += 10
            threats.append({"type": "high-entropy", "detail": f"URL entropy {entropy:.2f} (suspicious)"})

        # HTTP
        if parsed.scheme == 'http':
            score += 10
            threats.append({"type": "no-https", "detail": "Connection is not encrypted"})

        # URL length
        if len(url) > 200:
            score += 5
            threats.append({"type": "long-url", "detail": f"URL length {len(url)} chars"})

    except Exception:
        score += 10
        threats.append({"type": "parse-error", "detail": "URL could not be parsed"})

    return {
        "agent": "url-agent",
        "model": MODEL_NAME,
        "score": min(score, 100),
        "threats": threats
    }


# Removed _check_threat_apis because we now use fully offline threat caching


async def analyze_llm(url: str) -> dict:
    """Enhanced analysis using SmolLM2-1.7B-Instruct via Ollama and Threat APIs."""
    heuristic = analyze_heuristic(url)
    
    # Step 07 Architecture: Threat API Layer Lookups (OFFLINE)
    from backend.threat_cache import lookup_threat
    local_threat = lookup_threat(url)
    if local_threat:
        heuristic["threats"].append({"type": local_threat["type"], "detail": f"Matched in offline {local_threat['source']} feed"})
        heuristic["score"] = max(heuristic["score"], local_threat["risk"])

    prompt = f"""You are a cybersecurity URL analysis agent. Analyze this URL for phishing/malware indicators.
URL: {url}

Heuristic findings: {heuristic['threats']}

Provide a JSON response with:
- "risk_assessment": brief risk summary
- "additional_threats": any threats the heuristics may have missed
- "confidence": 0-100

Respond ONLY with valid JSON."""

    try:
        from backend.ollama_engine import generate_async, is_available
        if is_available():
            llm_response = await generate_async("url-agent", prompt)
            heuristic["llm_analysis"] = llm_response
        else:
            heuristic["llm_analysis"] = "AirLLM not installed"
    except Exception as e:
        heuristic["llm_analysis"] = f"LLM unavailable: {str(e)}"

    return heuristic
