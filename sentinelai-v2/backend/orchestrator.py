"""
SentinelAI v2.0 — LangGraph Orchestrator
Model: Qwen3.5 (quantized Q4) via Ollama
Coordinates all agents, routes runtime events, merges signals for verdict.
Uses LangGraph state-machine for parallel agent execution.
"""

import asyncio
import time
import httpx
from typing import TypedDict, Optional
from backend.agents import url_agent, content_agent, runtime_agent, exfil_agent, visual_agent, verdict_agent, tracker_agent, baseline_agent, campaign_agent
from backend import monitor

ORCHESTRATOR_MODEL = "qwen2.5:3b"


class ScanState(TypedDict):
    """State flowing through the LangGraph pipeline."""
    url: str
    hostname: str
    page_signals: Optional[dict]
    hook_events: list
    screenshot_b64: Optional[str]
    # Agent results
    url_result: Optional[dict]
    content_result: Optional[dict]
    runtime_result: Optional[dict]
    exfil_result: Optional[dict]
    visual_result: Optional[dict]
    tracker_result: Optional[dict]
    baseline_result: Optional[dict]
    campaign_result: Optional[dict]
    monitor_result: Optional[dict]
    # Final
    verdict: Optional[dict]
    timestamp: float


def _has_meaningful_page_signals(page_signals: Optional[dict]) -> bool:
    """Return True when we have enough page evidence to justify a deep scan."""
    if not page_signals:
        return False

    signal_keys = (
        "forms",
        "links",
        "scripts",
        "meta",
        "bodyTextPreview",
        "externalLinkCount",
        "scriptCount",
        "inlineScriptCount",
        "title",
    )
    return any(page_signals.get(key) for key in signal_keys)


async def run_url_agent(state: ScanState) -> dict:
    """Run URL + Intel Agent (SmolLM2-1.7B-Instruct)."""
    result = url_agent.analyze_heuristic(state["url"])
    return {"url_result": result}


async def run_content_agent(state: ScanState) -> dict:
    """Run Content Agent (Phi-4-mini-reasoning)."""
    if not state.get("page_signals"):
        return {"content_result": {"agent": "content-agent", "score": 0, "threats": []}}
    result = content_agent.analyze_heuristic(state["page_signals"])
    return {"content_result": result}


async def run_runtime_agent(state: ScanState) -> dict:
    """Run Runtime Agent (Phi-4-mini-reasoning shared)."""
    if not state.get("hook_events"):
        return {"runtime_result": {"agent": "runtime-agent", "score": 0, "threats": []}}
    result = runtime_agent.analyze_heuristic(state["hook_events"], state.get("hostname", ""))
    return {"runtime_result": result}


async def run_exfil_agent(state: ScanState) -> dict:
    """Run Exfil Agent (Qwen2.5-1.5B-Instruct)."""
    if not state.get("hook_events"):
        return {"exfil_result": {"agent": "exfil-agent", "score": 0, "threats": []}}
    result = exfil_agent.analyze_heuristic(state["hook_events"])
    return {"exfil_result": result}


async def run_visual_agent(state: ScanState) -> dict:
    """Run Visual Agent (SigLIP-2 + Gemma-3-2B-IT)."""
    screenshot_b64 = state.get("screenshot_b64")
    if screenshot_b64:
        try:
            result = await visual_agent.analyze_screenshot(
                screenshot_b64,
                state.get("page_signals")
            )
        except Exception:
            result = visual_agent.analyze_heuristic(state.get("page_signals") or {})
    else:
        result = visual_agent.analyze_heuristic(state.get("page_signals") or {})
    return {"visual_result": result}


async def run_tracker_agent(state: ScanState) -> dict:
    """Run Tracker Agent (heuristic)."""
    try:
        result = tracker_agent.analyze_heuristic(state.get("hook_events", []))
    except Exception:
        result = {"agent": "tracker-agent", "score": 0, "threats": []}
    return {"tracker_result": result}


async def run_baseline_agent(state: ScanState) -> dict:
    """Run Baseline Anomaly Agent (Tier 1)."""
    result = baseline_agent.check_baseline(state["hostname"], state.get("hook_events", []))
    for e in state.get("hook_events", []):
        baseline_agent.update_baseline(state["hostname"], e.get("hook", ""))
    return {"baseline_result": result}


async def run_campaign_agent(state: ScanState) -> dict:
    """Run Campaign Agent (Tier 2)."""
    ip = state.get("page_signals", {}).get("ip") if state.get("page_signals") else None
    result = campaign_agent.analyze_campaign(ip, state.get("hostname", ""))
    return {"campaign_result": result}


async def run_monitor_analysis(state: ScanState) -> dict:
    """Run Network Monitor Analysis on domains observed in hooks."""
    domains = []
    if state.get("hostname"):
        domains.append(state["hostname"])

    for domain in (state.get("page_signals", {}) or {}).get("outboundDomains", []):
        if domain:
            domains.append(domain)
    
    for e in state.get("hook_events", []):
        if e.get("hook") in ("fetch", "xhr", "beacon", "websocket"):
            url = e.get("data", {}).get("url", "")
            if url:
                domains.append(url)

    if len(domains) > 8:
        domains = domains[:8]
                
    try:
        result = monitor.scan_domains(domains)
    except Exception as e:
        print(f"[Orchestrator] Monitor Analysis error: {e}")
        result = {
            "agent": "monitor-analysis",
            "score": 0,
            "threats": [],
            "data_sharing": [],
            "blocking_tips": [],
            "domain_locations": {},
            "primary_location": "Unknown"
        }
    return {"monitor_result": result}


async def run_verdict_agent(state: ScanState) -> dict:
    """Run Verdict Agent (LFM2.5-2B-Thinking) — must run AFTER all other agents."""
    agent_results = {
        "url-agent": state.get("url_result", {}),
        "content-agent": state.get("content_result", {}),
        "runtime-agent": state.get("runtime_result", {}),
        "exfil-agent": state.get("exfil_result", {}),
        "visual-agent": state.get("visual_result", {}),
        "tracker-agent": state.get("tracker_result", {}),
        "baseline-agent": state.get("baseline_result", {}),
        "campaign-agent": state.get("campaign_result", {}),
        "monitor-analysis": state.get("monitor_result", {}),
    }
    result = verdict_agent.compute_verdict(agent_results)
    monitor_result = state.get("monitor_result", {}) or {}
    result["privacy_monitor"] = {
        "agent": "monitor-analysis",
        "score": monitor_result.get("score", 0),
        "summary": {
            "destination_count": len(monitor_result.get("data_sharing", [])),
            "primary_location": monitor_result.get("primary_location", "Unknown"),
        },
        "destinations": monitor_result.get("data_sharing", []),
        "domain_locations": monitor_result.get("domain_locations", {}),
        "blocking_tips": monitor_result.get("blocking_tips", []),
        "threats": monitor_result.get("threats", []),
    }
    return {"verdict": result}


async def orchestrate_scan(url: str, hostname: str = "",
                           page_signals: dict = None,
                           hook_events: list = None,
                           screenshot_b64: str = None) -> dict:
    """
    Main orchestration pipeline using parallel agent execution.
    Implements the LangGraph pattern: parallel analysis → merge → verdict.
    """
    state: ScanState = {
        "url": url,
        "hostname": hostname or "",
        "page_signals": page_signals,
        "hook_events": hook_events or [],
        "screenshot_b64": screenshot_b64,
        "url_result": None,
        "content_result": None,
        "runtime_result": None,
        "exfil_result": None,
        "visual_result": None,
        "tracker_result": None,
        "baseline_result": None,
        "campaign_result": None,
        "monitor_result": None,
        "verdict": None,
        "timestamp": time.time()
    }

    # Step 1: Run all 6 analysis agents

    # Step 1: Tier 1 Lightning Scan
    # We run URL agent and baseline checks here
    tier1_results = await asyncio.gather(
        run_url_agent(state),
        run_baseline_agent(state)
    )
    for r in tier1_results:
        state.update(r)
    
    score = state["url_result"].get("score", 0)
    baseline_score = state.get("baseline_result", {}).get("score", 0)
    
    has_page_evidence = _has_meaningful_page_signals(state.get("page_signals"))
    has_hook_evidence = bool(state.get("hook_events"))
    has_screenshot = bool(state.get("screenshot_b64"))
    should_run_deep_scan = has_page_evidence or has_hook_evidence or has_screenshot

    # Confidence threshold logic router
    confidence = 0.95 if (score == 0 and not should_run_deep_scan) or score > 75 else 0.70
    if baseline_score >= 50:
        confidence = 0.50  # Anomaly drops confidence, forces Tier 2

    # Always drop confidence if we have runtime network hooks or any richer evidence to analyze
    if should_run_deep_scan:
        confidence = min(confidence, 0.50)
    
    if confidence >= 0.92:
        # Tier 1 verdict fired, skip Tier 2
        level = "critical" if score >= 80 else "high" if score >= 75 else "medium" if score >= 40 else "low" if score >= 30 else "safe"
        state["verdict"] = {
            "composite_score": score,
            "level": level,
            "confidenceInterval": 5, # Highly confident
            "all_threats": state["url_result"].get("threats", []) + state.get("baseline_result", {}).get("threats", []),
            "recommendation": "Decided by Tier 1 Lightning Scan",
            "agent_breakdown": {
                "url-agent": {"rawScore": score},
                "baseline-agent": {"rawScore": baseline_score}
            },
            "action": "block" if level in ("critical", "high") else "warn" if level == "medium" else "allow",
            "data_sharing": state["url_result"].get("data_sharing", []),
            "blocking_tips": state["url_result"].get("blocking_tips", []),
            "scan_mode": "tier1"
        }
        return state

    # Step 2: Tier 2 Deep Scan
    results = await asyncio.gather(
        run_content_agent(state),
        run_runtime_agent(state),
        run_exfil_agent(state),
        run_visual_agent(state),
        run_tracker_agent(state),
        run_campaign_agent(state),
        run_monitor_analysis(state)
    )

    # Merge results into state
    for result in results:
        if isinstance(result, dict):
            state.update(result)

    # Step 3: Run Verdict Agent (depends on all others)
    verdict_result = await run_verdict_agent(state)
    state.update(verdict_result)
    
    # Add deep scan metadata
    if "verdict" in state and isinstance(state["verdict"], dict):
        state["verdict"]["scan_mode"] = "tier2"
        
        # v3: Learning step — Update IP reputation if verdict is high confidence
        final_score = state["verdict"].get("composite_score", 0)
        from backend.main import persistent
        ip = state.get("page_signals", {}).get("ip") if state.get("page_signals") else None
        if ip and ip != "127.0.0.1" and final_score > 50:
            existing_rep = persistent.get_reputation(ip) or {"risk_score": 0, "malicious_siblings": []}
            new_score = (existing_rep["risk_score"] + final_score) / 2 if existing_rep["risk_score"] > 0 else final_score
            siblings = existing_rep["malicious_siblings"]
            if state["hostname"] not in siblings:
                siblings.append(state["hostname"])
            persistent.update_reputation(ip, new_score, siblings)

    return state


async def quick_scan(url: str) -> dict:
    """URL-only quick scan (runs just the URL agent)."""
    result = await run_url_agent({"url": url, "hostname": "", "page_signals": None, "hook_events": [], "screenshot_b64": None,
                                   "url_result": None, "content_result": None, "runtime_result": None,
                                   "exfil_result": None, "visual_result": None, "tracker_result": None,
                                   "baseline_result": None, "campaign_result": None,
                                   "monitor_result": None,
                                   "verdict": None, "timestamp": time.time()})
    return result.get("url_result", {})
