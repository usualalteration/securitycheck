"""
v1/analyze - service info endpoint.

The actual per-model analysis is performed by the sibling action v1/analyze-model,
which the frontend calls once per model, sequentially, so Ollama only handles one
request at a time (avoids the "response not yet ready" 503).

This action only exposes a lightweight GET service descriptor used by the
frontend to discover the available models.
"""

MODELS = ["GLM 5.2", "Kimi K2.7 Code", "DeepSeek V4 Pro"]


def request_data(args):
    data = dict(args) if isinstance(args, dict) else {}
    body = data.get("body")
    if isinstance(body, str):
        try:
            import json
            body = json.loads(body)
        except Exception:
            body = {}
    merged = dict(body) if isinstance(body, dict) else {}
    ignored = {"body", "__ow_method", "__ow_headers", "__ow_path", "__ow_body"}
    merged.update({k: v for k, v in data.items() if k not in ignored})
    return merged


def main(args, ctx=None):
    method = (args.get("__ow_method") or args.get("method") or "GET").upper()
    if method == "GET":
        return {
            "ok": True,
            "service": "securitycheck",
            "models": MODELS,
            "description": "Analisi di sicurezza del codice sorgente con 3 modelli Ollama in parallelo.",
            "model_endpoint": "/api/my/v1/analyze-model",
        }
    # POST is intentionally not used anymore: the frontend orchestrates one
    # v1/analyze-model call per model sequentially.
    return {
        "ok": False,
        "error": "Usa /api/my/v1/analyze-model per analizzare un singolo modello.",
        "model_endpoint": "/api/my/v1/analyze-model",
        "models": MODELS,
    }