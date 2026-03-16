"""
SentinelAI v2.0 — AirLLM Inference Engine
Runs all AI models on low VRAM using HuggingFace transformers with 4-bit quantization.
Models are loaded on-demand and cached. Compatible with Python 3.13+.
Falls back to heuristic analysis if models unavailable.
"""

import os
import threading
from typing import Optional

# Global model cache and lock (only one model can generate at a time)
_models = {}
_tokenizers = {}
_lock = threading.Lock()

# HuggingFace model IDs for each agent
MODEL_REGISTRY = {
    "url-agent": "HuggingFaceTB/SmolLM2-0.35B-Instruct",
    "content-agent": "microsoft/Phi-3.5-mini-instruct",
    "runtime-agent": "microsoft/Phi-3.5-mini-instruct",
    "exfil-agent": "Qwen/Qwen2.5-1.5B-Instruct",
    "visual-agent": "google/gemma-3-2b-it",
    "verdict-agent": "LiquidAI/LFM-2b-Thinking",
    "context-engine": "microsoft/Phi-3.5-mini-instruct",
    "orchestrator": "Qwen/Qwen2.5-7B-Instruct",
    "baseline-agent": "microsoft/Phi-3.5-mini-instruct",
    "campaign-agent": "Qwen/Qwen2.5-1.5B-Instruct"
}

# Configuration
MAX_NEW_TOKENS = 256
CACHE_DIR = os.getenv("AIRLLM_CACHE", "./data/models")


def _get_device():
    """Detect best available device."""
    try:
        import torch
        if torch.cuda.is_available():
            return "cuda"
    except ImportError:
        pass
    return "cpu"


def load_model(agent_name: str):
    """
    Load a model for the given agent using HuggingFace transformers.
    Uses 4-bit quantization when bitsandbytes is available.
    Models with same HF ID share the instance.
    """
    model_id = MODEL_REGISTRY.get(agent_name)
    if not model_id:
        raise ValueError(f"Unknown agent: {agent_name}")

    # Check cache
    if model_id in _models:
        return _models[model_id], _tokenizers[model_id]

    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
        import torch

        print(f"[AirLLM] Loading {model_id} for {agent_name}...")

        tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            trust_remote_code=True,
            cache_dir=CACHE_DIR
        )

        # Try 4-bit quantization first, fallback to float16/auto
        model = None
        device = _get_device()

        if device == "cuda":
            try:
                from transformers import BitsAndBytesConfig
                bnb_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_quant_type="nf4"
                )
                model = AutoModelForCausalLM.from_pretrained(
                    model_id,
                    quantization_config=bnb_config,
                    device_map="auto",
                    trust_remote_code=True,
                    cache_dir=CACHE_DIR
                )
                print(f"[AirLLM] ✓ Loaded {model_id} (4-bit quantized, CUDA)")
            except Exception as e:
                print(f"[AirLLM] 4-bit quantization failed: {e}, trying float16...")

        if model is None:
            # Fallback: float16 on CUDA or float32 on CPU
            dtype = torch.float16 if device == "cuda" else torch.float32
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                torch_dtype=dtype,
                device_map="auto" if device == "cuda" else None,
                trust_remote_code=True,
                cache_dir=CACHE_DIR,
                low_cpu_mem_usage=True
            )
            if device == "cpu":
                model = model.to(device)
            print(f"[AirLLM] ✓ Loaded {model_id} ({dtype}, {device})")

        _models[model_id] = model
        _tokenizers[model_id] = tokenizer
        return model, tokenizer

    except Exception as e:
        print(f"[AirLLM] ✗ Failed to load {model_id}: {e}")
        raise


def generate(agent_name: str, prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
    """
    Generate text for the specified agent.
    Thread-safe — only one generation at a time.
    """
    with _lock:
        try:
            import torch

            model, tokenizer = load_model(agent_name)

            inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
            device = next(model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=True,
                    temperature=0.1,
                    top_p=0.9,
                    pad_token_id=tokenizer.eos_token_id
                )

            # Decode only new tokens (skip the prompt)
            new_tokens = outputs[0][inputs["input_ids"].shape[1]:]
            output = tokenizer.decode(new_tokens, skip_special_tokens=True)
            return output.strip()

        except Exception as e:
            return f"[AirLLM Error] {str(e)}"


async def generate_async(agent_name: str, prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
    """Async wrapper — runs in thread pool to avoid blocking FastAPI."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, generate, agent_name, prompt, max_new_tokens)


def is_available() -> bool:
    """Check if transformers + torch are installed and functional."""
    try:
        import transformers
        import torch
        return True
    except ImportError:
        return False


def get_model_info() -> dict:
    """Get info about registered and loaded models."""
    return {
        "registry": MODEL_REGISTRY,
        "loaded": list(_models.keys()),
        "device": _get_device(),
        "available": is_available(),
    }


def unload_all():
    """Unload all cached models to free memory."""
    global _models, _tokenizers
    _models = {}
    _tokenizers = {}
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except ImportError:
        pass
    print("[AirLLM] All models unloaded")
