"""
v1/analyze-model - Analyze source code with ONE AI model.

Provider-agnostic inference: the model is discovered dynamically by the sibling
action v1/models, which also detects the provider PROTOCOL. The frontend
selects a model id and passes it here (optionally with a `protocol` hint that
v1/models produced). Inference is then routed to the right API:

  openai-compatible -> POST {base}/v1/chat/completions   (Bearer)
  ollama            -> POST {base}/api/chat              (Bearer optional)
  anthropic         -> POST {base}/v1/messages          (x-api-key)
  gemini            -> POST {base}/v1beta/models/{model}:generateContent (?key=)

If the protocol hint is missing, the backend re-detects it from AI_API_HOST
with safe read-only probes (no inference requests are used for detection).

The model id is used VERBATIM as returned by the provider; it is never
transformed. The frontend only needs to send the selected model id (plus an
optional backend-derived protocol/provider hint).

Each call gets up to 3 minutes (180s) to connect and respond. The frontend
drives the retry loop: 1 attempt + 4 retries with 3s pauses (5 total). If all 5
fail the UI shows a "riprova" button. The backend performs a single attempt per
invocation, bounded by the 180s timeout.

The API key is never included in any response, log, or error message.

Input:
  - url | code: source to analyze
  - model:      exact provider model id (required)
  - model_name: optional friendly name for the report
  - protocol:   optional provider protocol hint (openai-compatible|ollama|
                anthropic|gemini) produced by v1/models
  - filename, language: optional hints
Output:
  { ok, source, model: <ModelResult> }
"""

import json
import re
import time
import urllib.request
import urllib.error
from urllib.parse import quote

DEFAULT_MODEL_TIMEOUT = 180
MAX_SOURCE_BYTES = 512 * 1024
MAX_DOWNLOAD_BYTES = 1024 * 1024

DETECT_TIMEOUT = 12

VALID_PROTOCOLS = ("openai-compatible", "ollama", "anthropic", "gemini")

SYSTEM_PROMPT = "Rispondi solo con JSON valido, senza testo aggiuntivo."

TRANSIENT_MARKERS = (
    "not yet ready", "loading model", "model is loading", "busy",
    "try again", "rate limit", "too many requests", "service unavailable",
)
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------
def request_data(args):
    data = dict(args) if isinstance(args, dict) else {}
    body = data.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except Exception:
            body = {}
    merged = dict(body) if isinstance(body, dict) else {}
    ignored = {"body", "__ow_method", "__ow_headers", "__ow_path", "__ow_body"}
    merged.update({k: v for k, v in data.items() if k not in ignored})
    return merged


def request_method(args):
    return (args.get("__ow_method") or args.get("method") or "POST").upper()


# ---------------------------------------------------------------------------
# URL helpers (avoid /v1/v1/...)
# ---------------------------------------------------------------------------
def _norm_base(host):
    return (host or "").strip().rstrip("/")


def _v1_base(base):
    return base if base.endswith("/v1") else base + "/v1"


def _v1beta_base(base):
    return base if base.endswith("/v1beta") else base + "/v1beta"


def _safe_url(url):
    return url.split("?", 1)[0] if "?" in url else url


# ---------------------------------------------------------------------------
# Source acquisition (unchanged behavior)
# ---------------------------------------------------------------------------
def guess_language(filename, code):
    if filename:
        m = re.search(r"\.([a-zA-Z0-9]+)$", filename)
        if m:
            ext = m.group(1).lower()
            ext_map = {
                "py": "Python", "js": "JavaScript", "jsx": "JavaScript",
                "ts": "TypeScript", "tsx": "TypeScript", "java": "Java",
                "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "cs": "C#",
                "go": "Go", "rs": "Rust", "rb": "Ruby", "php": "PHP",
                "pl": "Perl", "sh": "Shell", "bash": "Shell", "sql": "SQL",
                "kt": "Kotlin", "swift": "Swift", "scala": "Scala",
                "lua": "Lua", "r": "R", "dart": "Dart", "vue": "Vue",
                "svelte": "Svelte", "html": "HTML", "xml": "XML",
                "yml": "YAML", "yaml": "YAML",
            }
            if ext in ext_map:
                return ext_map[ext]
    sample = code[:4000].lower()
    if "def " in sample or ("import " in sample and "self" in sample):
        return "Python"
    if "function " in sample and "console.log" in sample:
        return "JavaScript"
    if "public class" in sample or "system.out" in sample:
        return "Java"
    return "non specificato"


def download_source(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "securitycheck/1.0 (+code analyzer)",
            "Accept": "text/plain, text/*, application/octet-stream, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        status = getattr(resp, "status", None) or resp.getcode()
        if status >= 400:
            raise ValueError(f"HTTP {status} scaricando l'URL")
        chunks = []
        total = 0
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError("File troppo grande (max 1 MB)")
            chunks.append(chunk)
        raw = b"".join(chunks)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    if "\x00" in text:
        raise ValueError("Il contenuto scaricato sembra binario, non codice sorgente")
    if len(text.strip()) == 0:
        raise ValueError("Il file scaricato e vuoto")
    return text


def acquire_source(data):
    url = (data.get("url") or "").strip()
    code = data.get("code")
    filename = (data.get("filename") or "").strip()
    if url and code:
        raise ValueError("Fornisci solo l'URL oppure solo il codice, non entrambi")
    if url:
        if not re.match(r"^https?://", url, re.I):
            raise ValueError("L'URL deve iniziare con http:// o https://")
        text = download_source(url)
        source_type = "url"
    elif code is not None and str(code).strip():
        text = str(code)
        source_type = "code"
    else:
        raise ValueError("Indica un URL valido oppure incolla il codice sorgente")
    if len(text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("Il codice supera il limite di 512 KB")
    language = (data.get("language") or "").strip() or guess_language(filename, text)
    lines = text.count("\n") + 1
    meta = {
        "type": source_type,
        "url": url or None,
        "filename": filename or None,
        "language": language,
        "size": len(text.encode("utf-8")),
        "lines": lines,
    }
    return text, meta


# ---------------------------------------------------------------------------
# Prompt + JSON extraction (unchanged)
# ---------------------------------------------------------------------------
def build_prompt(language, code):
    return (
        "Sei un esperto di application security e code review. Analizza il seguente "
        "codice sorgente e individua ogni vulnerabilita, problema di sicurezza, "
        "configurazione errata, credenziali o segreti esposti, injection (SQL/NoSQL/"
        "command/LDAP), XSS, path traversal, deserializzazione insicura, controlli "
        "di accesso mancanti, uso insicuro di crittografia, dipendenze a rischio, "
        "race condition, error handling che leaking informazioni, e qualsiasi altra "
        "criticita rilevante.\n\n"
        "Restituisci ESCLUSIVAMENTE un oggetto JSON valido (nessun testo prima o "
        "dopo, niente markdown fences) con esattamente questo schema:\n"
        "{\n"
        '  "risk_level": "critical|high|medium|low|none",\n'
        '  "summary": "riepilogo breve del livello di rischio del codice",\n'
        '  "findings": [\n'
        '    {\n'
        '      "title": "titolo breve della vulnerabilita",\n'
        '      "severity": "critical|high|medium|low|info",\n'
        '      "category": "categoria (es. SQL Injection, XSS, Hardcoded Secret)",\n'
        '      "description": "descrizione dettagliata del problema e perche e rischioso",\n'
        '      "line": "riga o intervallo o null",\n'
        '      "recommendation": "come mitigare o correggere il problema"\n'
        '    }\n'
        '  ]\n'
        "}\n\n"
        f"Linguaggio presunto del codice: {language}.\n"
        "Se non trovi vulnerabilita, restituisci risk_level \"none\" e findings vuoto.\n\n"
        "Codice da analizzare:\n"
        f"{code}"
    )


def extract_json(text):
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    candidate = match.group(0)
    try:
        return json.loads(candidate)
    except Exception:
        for end in range(len(candidate), 0, -1):
            try:
                return json.loads(candidate[:end])
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------------
# HTTP POST helper (credential-safe errors)
# ---------------------------------------------------------------------------
def _http_post_json(url, headers, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    h = dict(headers)
    h.setdefault("Content-Type", "application/json")
    h.setdefault("Accept", "application/json")
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", None) or resp.getcode()
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        # Provider error bodies are echoed but credentials are never in them.
        snippet = (err_body or e.reason or "")[:500]
        if e.code in (401, 403):
            raise RuntimeError("Autenticazione provider fallita (HTTP %d) su %s" % (e.code, _safe_url(url)))
        raise RuntimeError("Provider HTTP %d su %s: %s" % (e.code, _safe_url(url), snippet))
    except urllib.error.URLError as e:
        reason = e.reason if hasattr(e, "reason") else str(e)
        raise RuntimeError("Errore di rete verso %s: %s" % (_safe_url(url), reason))
    return status, body


def _http_get_json(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body) if body else {}


# ---------------------------------------------------------------------------
# Provider-aware inference (one attempt; frontend drives the retry loop)
# ---------------------------------------------------------------------------
def _messages(system, prompt):
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ]


def infer_openai(base, key, model, prompt, timeout):
    url = _v1_base(base) + "/chat/completions"
    headers = {}
    if key:
        headers["Authorization"] = "Bearer " + key
    payload = {
        "model": model,
        "messages": _messages(SYSTEM_PROMPT, prompt),
        "temperature": 0.2,
    }
    _, body = _http_post_json(url, headers, payload, timeout)
    data = json.loads(body)
    choices = data.get("choices") if isinstance(data, dict) else None
    if not choices:
        # Some OpenAI-compatible gateways return {"content": {...}} or {"response": ...}
        return str(data.get("response") or data.get("content") or "")
    msg = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
    return msg.get("content") or ""


def infer_ollama(base, key, model, prompt, timeout):
    url = base + "/api/chat"
    headers = {}
    if key:
        headers["Authorization"] = "Bearer " + key
    payload = {
        "model": model,
        "stream": False,
        "messages": _messages(SYSTEM_PROMPT, prompt),
        "options": {"temperature": 0.2},
    }
    _, body = _http_post_json(url, headers, payload, timeout)
    data = json.loads(body)
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError("Ollama: %s" % data.get("error"))
    msg = data.get("message") or {}
    return msg.get("content") or data.get("response") or ""


def infer_anthropic(base, key, model, prompt, timeout):
    url = _v1_base(base) + "/messages"
    headers = {"anthropic-version": "2023-06-01"}
    if key:
        headers["x-api-key"] = key
    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    _, body = _http_post_json(url, headers, payload, timeout)
    data = json.loads(body)
    content = data.get("content") if isinstance(data, dict) else None
    if not isinstance(content, list):
        return ""
    return "".join(
        str(b.get("text", "")) for b in content
        if isinstance(b, dict) and b.get("type") == "text"
    )


def infer_gemini(base, key, model, prompt, timeout):
    url = _v1beta_base(base) + "/models/" + quote(model, safe="") + ":generateContent"
    headers = {}
    if key:
        headers["x-goog-api-key"] = key
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "generationConfig": {"temperature": 0.2},
    }
    _, body = _http_post_json(url, headers, payload, timeout)
    data = json.loads(body)
    cands = data.get("candidates") if isinstance(data, dict) else None
    if not cands:
        return ""
    parts = cands[0].get("content", {}).get("parts", []) if isinstance(cands[0], dict) else []
    return "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))


_INFER = {
    "openai-compatible": infer_openai,
    "ollama": infer_ollama,
    "anthropic": infer_anthropic,
    "gemini": infer_gemini,
}


# ---------------------------------------------------------------------------
# Protocol detection fallback (safe read-only probes; no inference requests)
# ---------------------------------------------------------------------------
def _probe_get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = resp.read().decode("utf-8", errors="replace")
        status = getattr(resp, "status", None) or resp.getcode()
    return status, body


def _looks_openai(body):
    try:
        data = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("data"), list)


def _looks_ollama(body):
    try:
        data = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("models"), list)


def _looks_anthropic(body):
    try:
        data = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("data"), list) \
        and "display_name" in (data.get("data") or [{}])[0]


def _looks_gemini(body):
    try:
        data = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and isinstance(data.get("models"), list)


def detect_protocol(host, key):
    """Detect the provider protocol from AI_API_HOST via read-only probes."""
    base = _norm_base(host)
    if not base:
        return "openai-compatible"
    # 1) OpenAI-compatible /v1/models (Bearer)
    for url in (_v1_base(base) + "/models", base + "/models"):
        if url == base + "/models" and base.endswith("/v1"):
            continue
        headers = {"Accept": "application/json"}
        if key:
            headers["Authorization"] = "Bearer " + key
        try:
            _, body = _probe_get(url, headers, DETECT_TIMEOUT)
            if _looks_openai(body) and not _looks_anthropic(body):
                return "openai-compatible"
        except Exception:  # noqa: BLE001
            pass
    # 2) Ollama /api/tags
    try:
        headers = {"Accept": "application/json"}
        if key:
            headers["Authorization"] = "Bearer " + key
        _, body = _probe_get(base + "/api/tags", headers, DETECT_TIMEOUT)
        if _looks_ollama(body):
            return "ollama"
    except Exception:  # noqa: BLE001
        pass
    # 3) Anthropic /v1/models (x-api-key)
    try:
        headers = {"Accept": "application/json", "anthropic-version": "2023-06-01"}
        if key:
            headers["x-api-key"] = key
        _, body = _probe_get(_v1_base(base) + "/models", headers, DETECT_TIMEOUT)
        if _looks_anthropic(body):
            return "anthropic"
    except Exception:  # noqa: BLE001
        pass
    # 4) Gemini /v1beta/models
    try:
        headers = {"Accept": "application/json"}
        if key:
            headers["x-goog-api-key"] = key
        _, body = _probe_get(_v1beta_base(base) + "/models", headers, DETECT_TIMEOUT)
        if _looks_gemini(body):
            return "gemini"
    except Exception:  # noqa: BLE001
        pass
    # Fallback: assume OpenAI-compatible (most common).
    return "openai-compatible"


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze_one_model(host, api_key, model_id, model_name, prompt, protocol, timeout):
    out = {
        "id": model_id,
        "name": model_name or model_id,
        "ok": False,
        "risk_level": "none",
        "summary": "",
        "findings": [],
        "report": "",
        "error": None,
    }
    base = _norm_base(host)
    infer = _INFER.get(protocol, infer_openai)
    try:
        content = infer(base, api_key, model_id, prompt, timeout)
        parsed = extract_json(content) or {}
        out["report"] = content
        out["risk_level"] = str(parsed.get("risk_level") or "none").lower()
        out["summary"] = str(parsed.get("summary") or "").strip()
        findings = parsed.get("findings") if isinstance(parsed.get("findings"), list) else []
        norm = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            norm.append({
                "title": str(f.get("title") or "Senza titolo").strip(),
                "severity": str(f.get("severity") or "info").lower(),
                "category": str(f.get("category") or "Generale").strip(),
                "description": str(f.get("description") or "").strip(),
                "line": f.get("line"),
                "recommendation": str(f.get("recommendation") or "").strip(),
            })
        out["findings"] = norm
        out["ok"] = True
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
def main(args, ctx=None):
    method = request_method(args)
    if method == "GET":
        return {
            "ok": True,
            "service": "securitycheck-model",
            "models_endpoint": "/api/my/v1/models",
        }

    host = getattr(ctx, "AI_API_HOST", None) if ctx else None
    if not host:
        return {
            "ok": False,
            "error": "Provider AI non configurato. Imposta AI_API_HOST nel file .env e ridistribuisci.",
        }
    api_key = getattr(ctx, "AI_API_KEY", None) if ctx else None

    data = request_data(args)

    model_id = str(data.get("model") or "").strip()
    if not model_id:
        return {
            "ok": False,
            "error": "Nessun modello selezionato. Apri il selettore \"AI Model\" e scegli un modello.",
        }
    model_name = str(data.get("model_name") or "").strip() or model_id

    # Protocol hint (backend-derived from v1/models); re-detect if absent.
    protocol = str(data.get("protocol") or "").strip().lower()
    if protocol not in VALID_PROTOCOLS:
        protocol = detect_protocol(host, api_key)

    timeout = DEFAULT_MODEL_TIMEOUT
    req_timeout = data.get("timeout")
    if req_timeout:
        try:
            timeout = int(req_timeout) if int(req_timeout) > 0 else DEFAULT_MODEL_TIMEOUT
        except (TypeError, ValueError):
            pass

    try:
        code, meta = acquire_source(data)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except urllib.error.URLError as e:
        reason = e.reason if hasattr(e, "reason") else str(e)
        return {"ok": False, "error": f"Impossibile scaricare l'URL: {reason}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"Errore acquisizione sorgente: {e}"}

    prompt = build_prompt(meta["language"], code)
    model_result = analyze_one_model(host, api_key, model_id, model_name, prompt, protocol, timeout)

    return {
        "ok": True,
        "source": meta,
        "model": model_result,
        "protocol": protocol,
    }