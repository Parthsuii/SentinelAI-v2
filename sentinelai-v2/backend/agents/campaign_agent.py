"""
SentinelAI v3.0 — Campaign Correlation Agent (Tier 2)
Model: Qwen2.5-1.5B INT4
Looks across browsing history using Neo4j Threat Graph for multi-site patterns.
"""
def analyze_campaign(ip: str) -> dict:
    from backend.main import graph_store
    
    if not ip:
        return {"agent": "campaign-agent", "score": 0, "campaign_detected": False, "threats": []}
        
    siblings = graph_store.check_campaign(ip)
    
    threats = []
    score = 0
    if siblings:
        score = 85
        threats.append({
            "type": "campaign-correlation",
            "detail": f"Infrastructure shared with {len(siblings)} known malicious domains"
        })
        
        return {
            "agent": "campaign-agent",
            "score": score,
            "campaign_detected": True,
            "siblings": siblings,
            "threats": threats
        }
    return {"agent": "campaign-agent", "score": 0, "campaign_detected": False, "threats": []}
