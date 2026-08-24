"""
v1/analyze - service info endpoint.

The actual per-model analysis is performed by the sibling action v1/analyze-model,
which the frontend calls with the model id selected by the user from the
dynamic list discovered by v1/models.

This action only exposes a lightweight GET service descriptor. It no longer
hardcodes any model list: model discovery is delegated to v1/models.
"""


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
            "models_endpoint": "/api/my/v1/models",
            "description": "Analisi di sicurezza del codice sorgente con il modello AI selezionato.",
            "model_endpoint": "/api/my/v1/analyze-model",
        }
    # POST is intentionally not used anymore: the frontend orchestrates the
    # analysis through v1/analyze-model using the model selected from v1/models.
    return {
        "ok": False,
        "error": "Usa /api/my/v1/analyze-model per analizzare con il modello selezionato.",
        "model_endpoint": "/api/my/v1/analyze-model",
        "models_endpoint": "/api/my/v1/models",
    }