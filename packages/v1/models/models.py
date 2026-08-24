"""
v1/models - Provider-agnostic AI model discovery.

Discovers every text/code-generation model accessible with the configured
server-side AI_API_HOST + AI_API_KEY, without ever exposing the key to the
browser, and without hardcoding any model list.

Architecture:

  GET /api/my/v1/models
        ↓
  discover(AI_API_HOST, AI_API_KEY)
        ↓
  provider adapters (tried in host-hinted order, response shape is authoritative)
    ├── OpenAI-compatible   GET {base}/v1/models   (Bearer)        -> {"data":[...]}
    ├── Anthropic          GET {base}/v1/models    (x-api-key)      -> {"data":[...]}
    ├── Google Gemini      GET {base}/v1beta/models (?key= / header)-> {"models":[...]}
    └── Ollama             GET {base}/api/tags      (Bearer optional)-> {"models":[...]}
        ↓
  normalize -> filter -> default -> {ok, models, default, provider, protocol, ...}

Hostname is used only to choose the probe ORDER; the actual protocol is decided
by which adapter returns a valid model-listing response. Unknown hosts are
probed safely with read-only GET requests in the order /v1/models, /models,
/api/tags and the response format determines the protocol.

The API key is NEVER included in any response, log, error message, or reported
endpoint. Reported endpoints strip query-string credentials.
"""

import json
import urllib.request
import urllib.error
from urllib.parse import urlparse, quote

REQUEST_TIMEOUT = 20

# Substrings (matched case-insensitively against id/object/owned_by) that
# identify non-chat / non-text-generation models and must be excluded. This is
# a conservative name-based filter: it only removes models that are *clearly*
# not text generators. When a provider exposes real capability metadata
# (e.g. Gemini supportedGenerationMethods) we filter on that instead.
NON_CHAT_MARKERS = (
    "embed", "embedding",
    "rerank", "reranking",
    "moderat",
    "tts", "speech", "whisper", "transcri", "s2t", "stt",
    "dall-e", "image", "diffus", "vision-to-text",
    "audio", "realtime", "suno", "music", "video",
    "search",  # search/scrape-only variants
)

# Priority tokens for picking a sensible default. First match wins.
DEFAULT_PRIORITY = (
    "gpt-5", "gpt-4", "gpt-4o", "gpt-3.5", "gpt",
    "claude-sonnet", "claude-opus", "claude-haiku", "claude",
    "gemini-2", "gemini-1.5",
    "qwen", "deepseek", "kimi", "glm", "llama", "mistral", "codestral",
    "gemma", "command", "nova", "phi", "yi", "mixtral",
)

SYSTEM_PROMPT = "Rispondi solo con JSON valido, senza testo aggiuntivo."

# Known host -> display brand (used only for labeling, never for protocol
# decisions). Substring/hostname matches are intentional and lenient.
HOST_BRAND = (
    ("api.openai.com", "OpenAI"),
    ("api.anthropic.com", "Anthropic"),
    ("generativelanguage.googleapis.com", "Google Gemini"),
    ("api.mistral.ai", "Mistral"),
    ("api.groq.com", "Groq"),
    ("openrouter.ai", "OpenRouter"),
    ("api.together.xyz", "Together"),
    ("api.fireworks.ai", "Fireworks"),
    ("api.deepinfra.com", "DeepInfra"),
    "REGOLO",
)


# ---------------------------------------------------------------------------
# URL / host helpers
# ---------------------------------------------------------------------------
def _norm_base(host):
    """Strip trailing slashes; never produces /v1/v1/... downstream."""
    return (host or "").strip().rstrip("/")


def _hostname(base):
    try:
        return (urlparse(base).hostname or "").lower()
    except Exception:
        return ""


def _is_local(h):
    return h in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or h.startswith("192.168.") \
        or h.startswith("10.") or h.startswith("172.16.") or h.startswith("172.17.") \
        or h.startswith("172.18.") or h.startswith("172.19.") or h.startswith("172.2") \
        or h.startswith("172.3") or h == ""


def _v1_base(base):
    """Base for /v1/* endpoints, avoiding /v1/v1/..."""
    return base if base.endswith("/v1") else base + "/v1"


def _v1beta_base(base):
    return base if base.endswith("/v1beta") else base + "/v1beta"


def _provider_display(base):
    h = _hostname(base)
    for entry in HOST_BRAND:
        if entry == "REGOLO":
            if "regolo" in h:
                return "Regolo"
            continue
        host, name = entry
        if h == host or h.endswith("." + host) or host in h:
            return name
    if _is_local(h):
        return "Ollama"
    return "Custom"


# ---------------------------------------------------------------------------
# HTTP helpers (raise on >=400; never log credentials)
# ---------------------------------------------------------------------------
def _http_get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = resp.read().decode("utf-8", errors="replace")
        status = getattr(resp, "status", None) or resp.getcode()
    return status, body


def _strip_query(url):
    """Return the URL without its query string (for credential-safe reporting)."""
    if "?" in url:
        return url.split("?", 1)[0]
    return url


# ---------------------------------------------------------------------------
# Typed discovery failures (carry a credential-safe endpoint only)
# ---------------------------------------------------------------------------
class _AuthFail(Exception):
    def __init__(self, endpoint):
        super().__init__("auth")
        self.endpoint = _strip_query(endpoint)


class _NetFail(Exception):
    def __init__(self, endpoint, reason):
        super().__init__("net")
        self.endpoint = _strip_query(endpoint)
        self.reason = str(reason)


# ---------------------------------------------------------------------------
# Model normalization
# ---------------------------------------------------------------------------
def _norm_model(mid, name, provider_display, obj="model", mtype="text",
                 capabilities=None, raw=None):
    return {
        "id": str(mid).strip(),
        "name": (name or mid).strip() if (name or "").strip() else str(mid).strip(),
        "provider": provider_display,
        "object": obj,
        "type": mtype,
        "capabilities": capabilities or ["chat"],
        "raw": raw or {},
    }


def _is_non_chat(model_id, obj, owned_by):
    blob = " ".join([model_id or "", obj or "", owned_by or ""]).lower()
    return any(marker in blob for marker in NON_CHAT_MARKERS)


def _pick_default(models):
    if not models:
        return None
    ids = [m["id"].lower() for m in models]
    for token in DEFAULT_PRIORITY:
        for i, mid in enumerate(ids):
            if token in mid:
                return models[i]["id"]
    for i, mid in enumerate(ids):
        if any(t in mid for t in ("chat", "instruct", "code", "coder")):
            return models[i]["id"]
    return models[0]["id"]


# ---------------------------------------------------------------------------
# Adapters — each returns a normalized result dict or None (not this protocol),
# or raises _AuthFail / _NetFail.
# ---------------------------------------------------------------------------
def adapter_openai(base, key, timeout):
    """OpenAI-compatible: GET /v1/models (Bearer). Accepts {data:[...]}."""
    brand = _provider_display(base)
    urls = [_v1_base(base) + "/models", base + "/models"]
    seen = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        headers = {"Accept": "application/json", "User-Agent": "securitycheck/1.0 (+discovery)"}
        if key:
            headers["Authorization"] = "Bearer " + key
        try:
            status, body = _http_get(url, headers, timeout)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise _AuthFail(url)
            # 404 / 5xx -> not this endpoint, try next.
            continue
        except urllib.error.URLError as e:
            raise _NetFail(url, e.reason if hasattr(e, "reason") else str(e))
        except (ValueError, OSError):
            continue
        try:
            data = json.loads(body) if body else {}
        except (ValueError, TypeError):
            continue
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            continue
        models = []
        for item in items:
            if not isinstance(item, dict):
                continue
            mid = str(item.get("id") or "").strip()
            if not mid:
                continue
            obj = str(item.get("object") or "model").strip()
            owned_by = str(item.get("owned_by") or item.get("owner") or "").strip()
            if _is_non_chat(mid, obj, owned_by):
                continue
            models.append(_norm_model(mid, None, brand, obj, "text",
                                      ["chat", "code"], item))
        return {
            "protocol": "openai-compatible",
            "provider": brand,
            "source": "openai",
            "models": models,
            "endpoint": _strip_query(url),
        }
    return None


def adapter_anthropic(base, key, timeout):
    """Anthropic: GET /v1/models with x-api-key + anthropic-version."""
    brand = "Anthropic"
    url = _v1_base(base) + "/models"
    headers = {
        "Accept": "application/json",
        "User-Agent": "securitycheck/1.0 (+discovery)",
        "anthropic-version": "2023-06-01",
    }
    if key:
        headers["x-api-key"] = key
    try:
        status, body = _http_get(url, headers, timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise _AuthFail(url)
        return None
    except urllib.error.URLError as e:
        raise _NetFail(url, e.reason if hasattr(e, "reason") else str(e))
    try:
        data = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return None
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    models = []
    for item in items:
        if not isinstance(item, dict):
            continue
        mid = str(item.get("id") or "").strip()
        if not mid:
            continue
        name = str(item.get("display_name") or item.get("name") or "").strip()
        # Anthropic only lists Claude chat models; keep all, but still apply the
        # conservative name filter just in case.
        if _is_non_chat(mid, item.get("type", "model"), ""):
            continue
        models.append(_norm_model(mid, name or None, brand, "model", "text",
                                  ["chat"], item))
    return {
        "protocol": "anthropic",
        "provider": brand,
        "source": "anthropic",
        "models": models,
        "endpoint": _strip_query(url),
    }


def adapter_gemini(base, key, timeout):
    """Google Gemini: GET /v1beta/models (?key= or x-goog-api-key)."""
    brand = "Google Gemini"
    base_url = _v1beta_base(base) + "/models"
    headers = {"Accept": "application/json", "User-Agent": "securitycheck/1.0 (+discovery)"}
    if key:
        headers["x-goog-api-key"] = key
    url = base_url + ("&key=" if "?" in base_url else "?key=") + (key or "") if key else base_url
    try:
        status, body = _http_get(url, headers, timeout)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise _AuthFail(base_url)
        return None
    except urllib.error.URLError as e:
        raise _NetFail(base_url, e.reason if hasattr(e, "reason") else str(e))
    try:
        data = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return None
    items = data.get("models") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    models = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name_field = str(item.get("name") or "").strip()  # "models/gemini-2.5-pro"
        mid = name_field.replace("models/", "", 1) if name_field.startswith("models/") \
            else str(item.get("id") or name_field or "").strip()
        if not mid:
            continue
        display = str(item.get("displayName") or "").strip()
        methods = item.get("supportedGenerationMethods")
        if not isinstance(methods, list):
            methods = []
        # Capability-based filter: keep only models that support text content
        # generation. Excludes embed-only / image / tts models cleanly.
        if methods and "generateContent" not in methods:
            continue
        caps = [m for m in methods if isinstance(m, str)] or ["chat"]
        models.append(_norm_model(mid, display or None, brand, "model", "text",
                                  caps, item))
    return {
        "protocol": "gemini",
        "provider": brand,
        "source": "gemini",
        "models": models,
        "endpoint": _strip_query(base_url),
    }


def adapter_ollama(base, key, timeout):
    """Ollama: GET /api/tags (Bearer optional). Accepts {models:[...]}."""
    brand = "Ollama"
    urls = [base + "/api/tags", _v1_base(base) + "/models", base + "/models"]
    seen = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        headers = {"Accept": "application/json", "User-Agent": "securitycheck/1.0 (+discovery)"}
        if key:
            headers["Authorization"] = "Bearer " + key
        try:
            status, body = _http_get(url, headers, timeout)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise _AuthFail(url)
            continue
        except urllib.error.URLError as e:
            raise _NetFail(url, e.reason if hasattr(e, "reason") else str(e))
        try:
            data = json.loads(body) if body else {}
        except (ValueError, TypeError):
            continue
        items = data.get("models") if isinstance(data, dict) else None
        if not isinstance(items, list):
            continue
        models = []
        for item in items:
            if not isinstance(item, dict):
                continue
            mid = str(item.get("name") or item.get("model") or "").strip()
            if not mid:
                continue
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            fam = str(details.get("family") or "").strip()
            if _is_non_chat(mid, "model", fam):
                continue
            models.append(_norm_model(mid, None, brand, "model", "text",
                                      ["chat", "code"], item))
        return {
            "protocol": "ollama",
            "provider": brand,
            "source": "ollama",
            "models": models,
            "endpoint": _strip_query(url),
        }
    return None


def _adapter_order(base):
    """Host-hinted probe order. Hostname only orders; shape probing decides."""
    h = _hostname(base)
    if "anthropic" in h:
        return [adapter_anthropic, adapter_openai, adapter_gemini, adapter_ollama]
    if "generativelanguage" in h or "googleapis" in h:
        return [adapter_gemini, adapter_openai, adapter_anthropic, adapter_ollama]
    if _is_local(h) or "ollama" in h:
        return [adapter_ollama, adapter_openai, adapter_anthropic, adapter_gemini]
    return [adapter_openai, adapter_anthropic, adapter_gemini, adapter_ollama]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def _safe_error(message, error_type, endpoints=None):
    return {
        "ok": False,
        "error": message,
        "error_type": error_type,
        "models": [],
        "endpoints": endpoints or [],
    }


def discover_models(host, api_key):
    base = _norm_base(host)
    if not base:
        return _safe_error(
            "Provider AI non configurato. Imposta AI_API_HOST nel file .env e ridistribuisci.",
            "config",
        )

    order = _adapter_order(base)
    auth_endpoints = []
    net_error = None
    attempted = []

    for adapter in order:
        try:
            res = adapter(base, api_key, REQUEST_TIMEOUT)
        except _AuthFail as a:
            auth_endpoints.append(a.endpoint)
            attempted.append(a.endpoint)
            continue
        except _NetFail as n:
            if net_error is None:
                net_error = n
            attempted.append(n.endpoint)
            continue
        except Exception:  # noqa: BLE001
            continue
        if res is None:
            continue
        models = res.get("models") or []
        # "No models returned by provider" vs "No compatible text models found".
        if not models:
            return _safe_error(
                "No models returned by provider per la chiave API configurata.",
                "empty",
                [res.get("endpoint", "")],
            )
        return {
            "ok": True,
            "models": models,
            "default": _pick_default(models),
            "source": res.get("source"),
            "provider": res.get("provider"),
            "protocol": res.get("protocol"),
            "endpoint": res.get("endpoint"),
            "count": len(models),
        }

    # No adapter produced a model listing.
    if auth_endpoints:
        msg = "Unable to authenticate with provider. Verifica la chiave API configurata."
        if len(auth_endpoints) == 1:
            msg += " Endpoint: %s" % auth_endpoints[0]
        return _safe_error(msg, "auth", auth_endpoints)
    if net_error is not None:
        return _safe_error(
            "Unable to reach AI provider: %s. Endpoint: %s" % (net_error.reason, net_error.endpoint),
            "network",
            [net_error.endpoint],
        )
    eps = [e for e in attempted if e]
    tail = (" Endpoint provati: %s" % ", ".join(eps)) if eps else ""
    return _safe_error(
        "Model discovery endpoint not supported per l'HOST configurato." + tail,
        "api",
        eps,
    )


def request_method(args):
    return (args.get("__ow_method") or args.get("method") or "GET").upper()


def main(args, ctx=None):
    method = request_method(args)
    if method != "GET":
        return _safe_error(
            "Usa GET /api/my/v1/models per scoprire i modelli disponibili.",
            "method",
        )
    host = getattr(ctx, "AI_API_HOST", None) if ctx else None
    api_key = getattr(ctx, "AI_API_KEY", None) if ctx else None
    return discover_models(host, api_key)