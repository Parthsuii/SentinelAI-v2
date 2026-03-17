"""
SentinelAI v2.0 — FastAPI Gateway
Endpoints: /scan, /verdict, /history, /whitelist, /feedback
CORS enabled for Chrome extension communication.
"""

import time
import asyncio
import os
import subprocess
import sys
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional

from backend.orchestrator import orchestrate_scan, quick_scan
from backend.storage import EphemeralStore, VerdictEmbeddingStore, PersistentStore, GraphStore
from backend.context_engine import ContextEngine

# ── App Init ──
app = FastAPI(
    title="SentinelAI v2.0",
    description="Active Runtime Intelligence — Web Safety API",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Extension communicates from any origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Files ──
# Mount dashboard and popup for unified access
root_dir = os.path.dirname(os.path.dirname(__file__))
app.mount("/dashboard", StaticFiles(directory=os.path.join(root_dir, "dashboard"), html=True), name="dashboard")
app.mount("/popup", StaticFiles(directory=os.path.join(root_dir, "popup"), html=True), name="popup")

# ── Storage Init ──
ephemeral = EphemeralStore()
embeddings = VerdictEmbeddingStore()
persistent = PersistentStore()
graph_store = GraphStore()
context = ContextEngine(embedding_store=embeddings)


# ── Request/Response Models ──

class ScanRequest(BaseModel):
    url: str
    hostname: str = ""
    page_signals: Optional[dict] = None
    hook_events: Optional[list] = Field(default_factory=list)
    screenshot_b64: Optional[str] = None

class QuickScanRequest(BaseModel):
    url: str

class WhitelistRequest(BaseModel):
    hostname: str

class FeedbackRequest(BaseModel):
    url: str
    verdict_id: str = ""
    feedback: str
    is_correct: bool


# ── Endpoints ──

@app.get("/")
async def root():
    return {
        "name": "SentinelAI v2.0",
        "status": "active",
        "layers": 7,
        "hooks": 15,
        "agents": 6,
        "timestamp": time.time()
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}


@app.post("/scan")
async def scan(req: ScanRequest):
    """Full scan: runs all 6 agents in parallel via LangGraph orchestrator."""
    try:
        result = await orchestrate_scan(
            url=req.url,
            hostname=req.hostname,
            page_signals=req.page_signals,
            hook_events=req.hook_events or [],
            screenshot_b64=req.screenshot_b64
        )

        verdict = result.get("verdict", {})

        # Store in persistent storage
        monitor_result = result.get("monitor_result") or {}
        location_info = monitor_result.get("location_info")
        persistent.save_scan(
            url=req.url,
            hostname=req.hostname,
            score=verdict.get("composite_score", 0),
            level=verdict.get("level", "unknown"),
            threat_count=len(verdict.get("all_threats", [])),
            threats=verdict.get("all_threats", []),
            agent_breakdown=verdict.get("agent_breakdown", {}),
            location_info=location_info
        )

        # Store ephemeral event
        ephemeral.set_event(f"scan:{req.url}", {"verdict": verdict}, ttl_ms=300)

        return {
            "url": req.url,
            "verdict": verdict,
            "privacy_monitor": verdict.get("privacy_monitor", {}),
            "agent_results": {
                "url": result.get("url_result"),
                "content": result.get("content_result"),
                "runtime": result.get("runtime_result"),
                "exfil": result.get("exfil_result"),
                "visual": result.get("visual_result"),
                "tracker": result.get("tracker_result"),
                "monitor": result.get("monitor_result"),
            },
            "timestamp": time.time()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.post("/quick-scan")
async def quick_scan_endpoint(req: QuickScanRequest):
    """Quick URL-only scan."""
    try:
        result = await quick_scan(req.url)
        return {"url": req.url, "result": result, "timestamp": time.time()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/prewarm")
async def prewarm():
    """Pre-warm Tier 1 models."""
    try:
        # STUB: Ensure Tier 1 models (SmolLM2, etc) are loaded in memory
        from backend.agents.url_agent import MODEL_NAME
        return {"status": "ready"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/history")
async def get_history(limit: int = 100):
    """Get scan history."""
    history = persistent.get_history(limit)
    return {"history": history, "count": len(history)}


@app.delete("/history")
async def clear_history():
    """Clear scan history."""
    persistent.clear_history()
    return {"ok": True}


@app.get("/whitelist")
async def get_whitelist():
    """Get whitelisted domains."""
    return {"whitelist": persistent.get_whitelist()}


@app.post("/whitelist")
async def add_whitelist(req: WhitelistRequest):
    """Add domain to whitelist."""
    persistent.add_whitelist(req.hostname)
    return {"ok": True, "hostname": req.hostname}


@app.delete("/whitelist/{hostname}")
async def remove_whitelist(hostname: str):
    """Remove domain from whitelist."""
    persistent.remove_whitelist(hostname)
    return {"ok": True}


@app.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    """Submit user feedback on a verdict."""
    persistent.save_feedback(req.url, req.verdict_id, req.feedback, req.is_correct)
    return {"ok": True}


@app.get("/similar/{url:path}")
async def find_similar(url: str, n: int = 5):
    """Find similar past verdicts via embedding search."""
    results = await context.find_similar_verdicts(url, n)
    return {"similar": results}


@app.websocket("/runtime")
async def runtime_websocket(websocket: WebSocket):
    """WebSocket endpoint for streaming runtime hook events from the extension."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            events = data.get("events", [])
            url = data.get("url", "")
            hostname = data.get("hostname", "")

            # Store ephemeral events
            if events:
                ephemeral.set_event(f"runtime:{url}", {"events": events}, ttl_ms=5000)

            # Quick risk assessment on incoming events
            risk_signals = []
            for event in events:
                hook = event.get("hook", "")
                if hook in ("eval", "form", "cookie", "permission"):
                    risk_signals.append({"hook": hook, "risk": "high"})
                elif hook in ("fetch", "xhr", "beacon", "websocket"):
                    risk_signals.append({"hook": hook, "risk": "medium"})

            # Send back real-time risk update
            await websocket.send_json({
                "type": "risk_update",
                "url": url,
                "event_count": len(events),
                "risk_signals": risk_signals,
                "timestamp": time.time()
            })
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


@app.get("/models")
async def get_models():
    """Get available Ollama models."""
    from backend.ollama_engine import get_model_info
    return get_model_info()


# ── Startup/Shutdown ──

@app.on_event("startup")
async def startup():
    from backend.ollama_engine import is_available
    ollama_status = "connected" if is_available() else "NOT RUNNING"
    print("SentinelAI v2.0 API started")
    print(f"   Layers: 7 | Hooks: 15 | Agents: 6")
    print(f"   Storage: Redis + ChromaDB + SQLite")
    print(f"   Ollama: {ollama_status}")
    
    # Pre-load bulky ML models in a background thread so the API doesn't hang on the first request
    def preload_models():
        print("[Startup] Pre-loading ML models in background...")
        try:
            context._get_embedder()
            from backend.agents.visual_agent import _load_siglip
            _load_siglip()
            print("[Startup] ML pre-loading complete.")
        except Exception as e:
            print(f"[Startup] ML pre-load warning: {e}")

    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, preload_models)
    
    # Launch monitor.py with the same interpreter and UTF-8 output so the
    # child process doesn't crash on Windows console encoding.
    monitor_path = os.path.join(os.path.dirname(__file__), "monitor.py")
    monitor_stdout_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "monitor_stdout.log")
    monitor_stderr_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "monitor_stderr.log")
    monitor_env = os.environ.copy()
    monitor_env["PYTHONIOENCODING"] = "utf-8"

    try:
        monitor_stdout = open(monitor_stdout_path, "a", encoding="utf-8")
        monitor_stderr = open(monitor_stderr_path, "a", encoding="utf-8")
        subprocess.Popen(
            [sys.executable, monitor_path],
            env=monitor_env,
            stdout=monitor_stdout,
            stderr=monitor_stderr,
            cwd=os.path.dirname(os.path.dirname(__file__)),
        )
        print(f"[Startup] Monitor process launched via {sys.executable}")
    except Exception as e:
        print(f"[Startup] Monitor launch warning: {e}")

    from backend.threat_cache import start_background_updater, update_feeds
    start_background_updater()
    asyncio.create_task(update_feeds())

    async def lora_check_job():
        while True:
            from backend.main import persistent
            feedback_count = len(persistent.get_feedback(limit=201))
            if feedback_count >= 200:
                print(f"[LoRA] Triggering fine-tuning with {feedback_count} samples...")
                import sys, os
                scripts_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts")
                if scripts_path not in sys.path: sys.path.append(scripts_path)
                from lora_finetune import run_lora_finetune
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, run_lora_finetune)
            await asyncio.sleep(3600)  # Check every hour

    asyncio.create_task(lora_check_job())


@app.on_event("shutdown")
async def shutdown():
    ephemeral.cleanup_memory()
    context.cleanup_old_sessions()
    graph_store.close()
    print("SentinelAI v2.0 API shutdown")
