"""Read-only vMaaS model discovery for dashboard status."""
import os
from urllib.parse import urlsplit
import requests
import streamlit as st

def fetch_vmaas_models() -> dict:
    token = os.getenv("VMAAS_API_KEY", "").strip()
    model = os.getenv("VMAAS_MODEL", "").strip()
    models_url = os.getenv("VMAAS_MODELS_URL", "https://aiplatform.viettelidc.com.vn/apis/v2/models").strip()
    parsed = urlsplit(models_url)
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    safe_endpoint = f"{parsed.scheme}://{host}{parsed.path}"
    if not token:
        return {"status": "API key missing", "model": model, "endpoint": safe_endpoint, "models": [], "detail": "Set VMAAS_API_KEY in .env"}
    try:
        response = requests.get(models_url, headers={"Authorization": f"Bearer {token}"}, timeout=(5, 12))
        if not response.ok:
            return {"status": f"HTTP {response.status_code}", "model": model, "endpoint": safe_endpoint, "models": [], "detail": response.text[:250]}
        payload = response.json()
        models = payload if isinstance(payload, list) else payload.get("data", payload.get("models", []))
        if isinstance(models, dict):
            models = models.get("data", [])
        model_ids = [str(item.get("id") or item.get("name")) for item in models if isinstance(item, dict)]
        selected = next((item for item in models if isinstance(item, dict) and str(item.get("id") or item.get("name")) == model), {})
        facts = []
        for key in ("context_length", "max_tokens", "max_model_len", "status", "object"):
            if key in selected and isinstance(selected[key], (str, int, float, bool)):
                facts.append(f"{key}: {selected[key]}")
        return {"status": "Connected", "model": model, "endpoint": safe_endpoint,
                "models": model_ids, "selected_found": model in model_ids, "facts": facts, "detail": ""}
    except requests.RequestException as exc:
        return {"status": "Unavailable", "model": model, "endpoint": safe_endpoint,
                "models": [], "detail": type(exc).__name__}
    except (ValueError, TypeError, AttributeError) as exc:
        return {"status": "Unexpected response", "model": model, "endpoint": safe_endpoint,
                "models": [], "detail": type(exc).__name__}
