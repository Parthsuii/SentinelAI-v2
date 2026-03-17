"""
SentinelAI v2.0 — Visual Clone Detection Agent
Models: SigLIP-2 (vision encoder) + Gemma-3-2B-IT (layout reasoning)
Tasks: encode site logos, compare with brand database, detect cloned layouts
"""

import io
import base64
from typing import Optional

VISION_MODEL = "siglip2"         # Vision encoder (google/siglip-base-patch16-224)
LAYOUT_MODEL = "gemma3:2b"       # Layout reasoning via Ollama

# Lazy-loaded SigLIP
_siglip_model = None
_siglip_processor = None

def _load_siglip():
    global _siglip_model, _siglip_processor
    if _siglip_model is None:
        try:
            from transformers import AutoProcessor, AutoModel
            _siglip_processor = AutoProcessor.from_pretrained("google/siglip-base-patch16-224")
            _siglip_model = AutoModel.from_pretrained("google/siglip-base-patch16-224")
            print("[VisualAgent] Loaded SigLIP-2 vision encoder")
        except ImportError:
            pass
        except Exception as e:
            print(f"[VisualAgent] Failed to load SigLIP: {e}")
    return _siglip_model, _siglip_processor

# Mock Brand Vision Hash DB for the architecture demo
BRAND_VISION_DB = {
    "paypal": "a photo of a paypal login page",
    "google": "a photo of a Google login page",
    "microsoft": "a photo of a Microsoft login page"
}

SAFE_VISUAL_HOSTS = {
    "microsoftonline.com",
    "googleusercontent.com",
    "accounts.google.com",
    "icloud.com",
    "live.com",
    "office.com",
}


def analyze_heuristic(signals: dict) -> dict:
    """Heuristic visual analysis based on page signals."""
    threats = []
    score = 0
    hostname = signals.get('hostname', '')
    title = (signals.get('title') or '').lower()
    body_preview = (signals.get('bodyTextPreview') or '').lower()

    lowered_host = hostname.lower()
    for brand in BRAND_VISION_DB.keys():
        if lowered_host in SAFE_VISUAL_HOSTS:
            continue
        if brand in lowered_host and not lowered_host.endswith(brand + ".com"):
            score += 20
            threats.append({
                "type": "domain-brand-mismatch", 
                "detail": f"Domain contains {brand} but is not standard brand domain"
            })

    # Check for login form heuristics
    forms = signals.get('forms', [])
    password_forms = [f for f in forms if f.get('hasPassword')]
    if password_forms and "login" in hostname and any(brand in title for brand in BRAND_VISION_DB.keys()) and lowered_host not in SAFE_VISUAL_HOSTS:
        score += 8
        threats.append({
            "type": "login-form-detected",
            "detail": f"Brand-themed login page detected on {hostname}"
        })

    auth_keywords = ("sign in", "login", "log in", "verify", "account", "password")
    if password_forms and any(keyword in title or keyword in body_preview for keyword in auth_keywords):
        score += 15
        threats.append({
            "type": "auth-themed-ui",
            "detail": "Visual login/account theme detected alongside a credential form"
        })

    if lowered_host in SAFE_VISUAL_HOSTS and score > 0:
        score *= 0.4

    if len(signals.get('iframes', [])) >= 3:
        score += 10
        threats.append({
            "type": "iframe-heavy-layout",
            "detail": "Page uses multiple iframe embeds, which can indicate cloaked UI layers"
        })

    return {
        "agent": "visual-agent",
        "model": VISION_MODEL,
        "score": min(score, 100),
        "threats": threats,
        "llm_analysis": None
    }


async def analyze_screenshot(screenshot_b64: str, page_signals=None) -> dict:
    """Analyze a page screenshot for visual impersonation using SigLIP-2 and local LLM."""
    if page_signals is None:
        page_signals = {}
    heuristic = analyze_heuristic(page_signals)
    
    # Step 10 Architecture Implementation: SigLIP-2 Clone Detection
    try:
        model, processor = _load_siglip()
        if model and processor and screenshot_b64:
            from PIL import Image
            import torch
            
            # Decode image
            img_data = base64.b64decode(screenshot_b64.split(",")[-1] if "," in screenshot_b64 else screenshot_b64)
            image = Image.open(io.BytesIO(img_data)).convert("RGB")
            
            # Zero-Shot text-to-image similarity to map against known visual brand references
            texts = list(BRAND_VISION_DB.values())
            brands = list(BRAND_VISION_DB.keys())
            
            inputs = processor(text=texts, images=image, padding="max_length", return_tensors="pt")
            
            with torch.no_grad():
                outputs = model(**inputs)
                
            logits_per_image = outputs.logits_per_image
            probs = torch.sigmoid(logits_per_image).squeeze().tolist()
            
            # Check if any brand matches heavily
            if not isinstance(probs, list): probs = [probs]
                
            for idx, brand in enumerate(brands):
                if probs[idx] > 0.85:  # 85%+ visual match
                    heuristic["score"] += 80
                    heuristic["threats"].append({
                        "type": "visual-clone",
                        "detail": f"SigLIP-2 detected 85%+ visual match for {brand}"
                    })
    except Exception as e:
        print(f"[VisualAgent] SigLIP processing error: {e}")

    url = page_signals.get("url", "unknown_url") if isinstance(page_signals, dict) else "unknown_url"
    prompt = f"""You are a visual layout expert. Review these page signals for a site:
URL: {url}
Findings: {heuristic['threats']}
Is this a fraudulent clone? Respond ONLY with valid JSON."""

    try:
        from backend.ollama_engine import generate_async, is_available
        if is_available():
            heuristic["llm_analysis"] = await generate_async("visual-agent", prompt)
        else:
            heuristic["llm_analysis"] = "Ollama not installed"
    except Exception as e:
        heuristic["llm_analysis"] = f"LLM unavailable: {str(e)}"

    return heuristic
