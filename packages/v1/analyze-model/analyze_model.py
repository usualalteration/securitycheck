"""
v1/analyze-model - Analyze source code with ONE Ollama model.

This is the single-model workhorse. The frontend calls it once per model,
sequentially (one after another), so Ollama only ever handles one request at a
time. That avoids the "response not yet ready" 503 that Ollama returns when it is
still loading a model or when several requests contend for the runtime.

Each call gets up to 3 minutes (180s) to connect and respond. The frontend
drives the retry loop: 1 attempt + 4 retries with 3s pauses (5 total). If all 5
fail the UI shows a "riprova" button for that model. The backend therefore
performs a single attempt per invocation, bounded by the 180s timeout.

Input:
  - url:    URL of a raw source file to download and validate, OR
  - code:   source code pasted directly
  - model:  model id (glm-5.2 | kimi-k2.7-code | deepseek-v4-pro)
  - filename, language: optional hints
Output:
  { ok, source, model: <ModelResult> }
"""

import json
import re
import time
import urllib.request
import urllib.error

MODELS = {
    "glm-5.2": {"id": "glm-5.2", "name": "GLM 5.2", "tag": "glm-5.2"},
    "kimi-k2.7-code": {"id": "kimi-k2.7-code", "name": "Kimi K2.7 Code", "tag": "kimi-k2.7-code"},
    "deepseek-v4-pro": {"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro", "tag": "deepseek-v4-pro"},
}

# Per-call timeout: give the model up to 3 minutes (180s) to connect and
# respond. The frontend drives the multi-attempt retry loop (4 retries with
# 3s pauses -> 5 attempts total), so the backend performs a single attempt
# per invocation. This keeps each HTTP request bounded and predictable.
DEFAULT_MODEL_TIMEOUT = 180
MAX_SOURCE_BYTES = 512 * 1024
MAX_DOWNLOAD_BYTES = 1024 * 1024

# Single attempt per call: the frontend handles the retry loop and shows the
# "riprova" state on the button after 5 total failures.
MAX_RETRIES = 0
RETRY_BACKOFF = [3]  # seconds (unused when MAX_RETRIES == 0)
TRANSIENT_MARKERS = (
    "not yet ready",
    "loading model",
    "model is loading",
    "busy",
    "try again",
    "rate limit",
    "too many requests",
    "service unavailable",
)
# HTTP status codes that are worth retrying (model loading / cloud busy / rate limit).
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
# Source acquisition
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
# Ollama interaction (with retry for "response not yet ready")
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


def _is_transient(err):
    """True when an error looks like a transient Ollama loading/busy state."""
    msg = str(err).lower()
    return any(m in msg for m in TRANSIENT_MARKERS)


def call_ollama_with_retry(host, model_tag, prompt, timeout, api_key=None):
    """
    Call Ollama /api/chat (stream:false) for one model.

    Retries on HTTP 429/503 "response not yet ready" or other transient
    loading/busy/rate-limit errors, sleeping with backoff between attempts.
    This lets Ollama (local or cloud) finish loading the model and respond,
    instead of failing fast. When api_key is provided (Ollama Cloud) it is sent
    as a Bearer token.
    """
    base = host.rstrip("/")
    url = base + "/api/chat"
    payload = json.dumps({
        "model": model_tag,
        "stream": False,
        "messages": [
            {"role": "system", "content": "Rispondi solo con JSON valido, senza testo aggiuntivo."},
            {"role": "user", "content": prompt},
        ],
        "options": {"temperature": 0.2},
    }).encode("utf-8")

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    last_error = None
    for attempt in range(MAX_RETRIES + 1):
        req = urllib.request.Request(
            url,
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read().decode("utf-8")
            data = json.loads(raw)
            # Ollama can return 200 with an error body when the model is busy.
            if isinstance(data, dict) and data.get("error"):
                err_msg = str(data.get("error"))
                if _is_transient(err_msg) and attempt < MAX_RETRIES:
                    last_error = err_msg
                    time.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                    continue
                raise RuntimeError(f"Ollama: {err_msg}")
            msg = data.get("message") or {}
            content = msg.get("content") or data.get("response") or ""
            return content
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            err_text = body or e.reason or str(e)
            # Auth errors are not transient: surface them clearly.
            if e.code in (401, 403):
                raise RuntimeError(
                    f"Ollama autenticazione fallita (HTTP {e.code}). "
                    "Verifica OLLAMA_API_KEY per Ollama Cloud."
                )
            # 429/503 "response not yet ready" / rate limit / model loading.
            if (e.code in RETRYABLE_HTTP_CODES or _is_transient(err_text)) and attempt < MAX_RETRIES:
                last_error = err_text
                time.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                continue
            raise RuntimeError(f"Ollama HTTP {e.code}: {err_text}")
        except urllib.error.URLError as e:
            # Network/timeout level: retry only if it looks transient.
            reason = e.reason if hasattr(e, "reason") else str(e)
            if _is_transient(reason) and attempt < MAX_RETRIES:
                last_error = reason
                time.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                continue
            raise
    # Exhausted retries.
    raise RuntimeError(
        f"Ollama non ha risposto dopo {MAX_RETRIES} tentativi"
        + (f" (ultimo errore: {last_error})" if last_error else "")
    )


def analyze_one_model(host, model, prompt, timeout, api_key=None):
    out = {
        "id": model["id"],
        "name": model["name"],
        "ok": False,
        "risk_level": "none",
        "summary": "",
        "findings": [],
        "report": "",
        "error": None,
    }
    try:
        content = call_ollama_with_retry(host, model["tag"], prompt, timeout, api_key=api_key)
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
            "models": [m["name"] for m in MODELS.values()],
        }

    host = getattr(ctx, "OLLAMA_HOST", None) if ctx else None
    if not host:
        return {
            "ok": False,
            "error": "Ollama non configurato. Imposta OLLAMA_HOST nel file .env e ridistribuisci.",
        }
    api_key = getattr(ctx, "OLLAMA_API_KEY", None) if ctx else None

    data = request_data(args)

    model_id = str(data.get("model") or "").strip()
    if model_id not in MODELS:
        return {
            "ok": False,
            "error": f"Modello non valido: {model_id or '(vuoto)'}. Usa uno tra: "
                     + ", ".join(MODELS.keys()),
        }
    model = MODELS[model_id]

    # No timeout cap: the caller may pass an explicit timeout, otherwise we
    # wait indefinitely for the model to respond when it is free.
    timeout = DEFAULT_MODEL_TIMEOUT
    req_timeout = data.get("timeout")
    if req_timeout:
        try:
            timeout = int(req_timeout) if int(req_timeout) > 0 else None
        except (TypeError, ValueError):
            pass

    # Acquire and validate the source code.
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
    model_result = analyze_one_model(host, model, prompt, timeout, api_key=api_key)

    return {
        "ok": True,
        "source": meta,
        "model": model_result,
    }