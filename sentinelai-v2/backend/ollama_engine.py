"""
SentinelAI v2.0 — Ollama Inference Engine
Runs all AI models locally via Ollama REST API at localhost:11434.
Models are pulled on-demand. Falls back to heuristic analysis if Ollama unavailable.
"""

import httpx
from typing import Optional

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_STATUS_TTL_SECONDS = 5.0
OLLAMA_ASYNC_TIMEOUT_SECONDS = 2.0
OLLAMA_SYNC_TIMEOUT_SECONDS = 10.0
_availability_cache = {
    "value": False,
    "expires_at": 0.0,
}

# Ollama model tags for each agent
MODEL_REGISTRY = {
    "url-agent": "smollm2:1.7b",
    "content-agent": "phi4-mini",
    "runtime-agent": "phi4-mini",           # Shared with content-agent
    "exfil-agent": "qwen2.5:1.5b",
    "visual-agent": "gemma:2b",             # Fixed tag: gemma:2b instead of gemma3:2b
    "verdict-agent": "qwen2.5:1.5b",
    "context-engine": "phi3.5",
    "orchestrator": "qwen2.5:3b",
}

MAX_NEW_TOKENS = 256


async def generate_async(agent_name: str, prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
    """
    Generate text for the specified agent using Ollama REST API.
    """
    model = MODEL_REGISTRY.get(agent_name)
    if not model:
        return f"[Ollama Error] Unknown agent: {agent_name}"

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_ASYNC_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": max_new_tokens,
                        "temperature": 0.1,
                        "top_p": 0.9,
                    }
                }
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
    except httpx.ConnectError:
        return "[Ollama Error] Cannot connect to Ollama at localhost:11434. Is Ollama running?"
    except httpx.TimeoutException:
        return "[Ollama Error] Request timed out"
    except Exception as e:
        return f"[Ollama Error] {str(e)}"


def generate(agent_name: str, prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
    """Synchronous generation wrapper."""
    model = MODEL_REGISTRY.get(agent_name)
    if not model:
        return f"[Ollama Error] Unknown agent: {agent_name}"

    try:
        with httpx.Client(timeout=OLLAMA_SYNC_TIMEOUT_SECONDS) as client:
            resp = client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": max_new_tokens,
                        "temperature": 0.1,
                        "top_p": 0.9,
                    }
                }
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
    except Exception as e:
        return f"[Ollama Error] {str(e)}"


def is_available() -> bool:
    """Check if Ollama is running and reachable."""
    import time

    now = time.time()
    if _availability_cache["expires_at"] > now:
        return _availability_cache["value"]

    try:
        with httpx.Client(timeout=0.5) as client:
            resp = client.get(f"{OLLAMA_BASE_URL}/api/tags")
            available = resp.status_code == 200
    except Exception:
        available = False

    _availability_cache["value"] = available
    _availability_cache["expires_at"] = now + OLLAMA_STATUS_TTL_SECONDS
    return available


def get_model_info() -> dict:
    """Get info about available Ollama models."""
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{OLLAMA_BASE_URL}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                return {
                    "registry": MODEL_REGISTRY,
                    "available_models": [m.get("name") for m in models],
                    "available": True,
                }
    except Exception:
        pass
    return {
        "registry": MODEL_REGISTRY,
        "available_models": [],
        "available": False,
    }
