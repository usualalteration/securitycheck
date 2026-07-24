"""
v1/analyze - Security code analysis via three Ollama models in parallel.

Accepts either:
  - url:   a URL to a raw source file (raw GitHub / Gist) to download and validate
  - code:  source code pasted directly by the user
Optional:
  - language: hint about the programming language (auto-detected otherwise)
  - filename:  optional filename hint (used for display only)

Calls three Ollama models in parallel (GLM 5.2, Kimi K2.7 Code, DeepSeek V4 Pro),
collects structured findings, then produces a comparison:
  - vulnerabilities common to multiple models
  - vulnerabilities found only by some models
  - overall risk level and conclusive summary

Ollama endpoint comes from ctx.OLLAMA_HOST (bound secret). When empty/missing the
action fails closed (the generated wrapper raises before reaching here).
"""

import json
import re
import concurrent.futures
import urllib.request
import urllib.error

# Models requested by the user (see https://ollama.com/library/...).
MODELS = [
    {"id": "glm-5.2", "name": "GLM 5.2", "tag": "glm-5.2"},
    {"id": "kimi-k2.7-code", "name": "Kimi K2.7 Code", "tag": "kimi-k2.7-code"},
    {"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro", "tag": "deepseek-v4-pro"},
]

# Severity ranking used for aggregation.
SEVERITY_SCORE = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "none": 0,
}
SEVERITY_LABEL_IT = {
    "critical": "Critico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Basso",
    "info": "Info",
    "none": "Nessuno",
}

DEFAULT_TIMEOUT = 180  # seconds per model HTTP call
MAX_SOURCE_BYTES = 512 * 1024  # 512 KB safety cap for downloaded/pasted code
MAX_DOWNLOAD_BYTES = 1024 * 1024  # 1 MB streaming cap for URL download


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
    ignored = {
        "body",
        "__ow_method",
        "__ow_headers",
        "__ow_path",
        "__ow_body",
    }
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
                "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "cxx": "C++",
                "cs": "C#", "go": "Go", "rs": "Rust", "rb": "Ruby",
                "php": "PHP", "pl": "Perl", "sh": "Shell", "bash": "Shell",
                "sql": "SQL", "kt": "Kotlin", "swift": "Swift",
                "scala": "Scala", "lua": "Lua", "r": "R", "dart": "Dart",
                "vue": "Vue", "svelte": "Svelte", "html": "HTML",
                "xml": "XML", "yml": "YAML", "yaml": "YAML",
            }
            if ext in ext_map:
                return ext_map[ext]
    sample = code[:4000].lower()
    if "def " in sample or "import " in sample and "self" in sample:
        return "Python"
    if "function " in sample and "console.log" in sample:
        return "JavaScript"
    if "public class" in sample or "system.out" in sample:
        return "Java"
    return "non specificato"


def download_source(url):
    """Download raw source from a URL and validate it is text content."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "securitycheck/1.0 (+code analyzer)",
            "Accept": "text/plain, text/*, application/octet-stream, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - user-supplied URL
        status = getattr(resp, "status", None) or resp.getcode()
        if status >= 400:
            raise ValueError(f"HTTP {status} scaricando l'URL")

        # Stream with a hard cap to avoid pulling huge binaries.
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

    # Try UTF-8 first, fall back to latin-1 to avoid crashes on odd encodings.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")

    # Reject obvious binary content.
    if "\x00" in text:
        raise ValueError("Il contenuto scaricato sembra binario, non codice sorgente")
    if len(text.strip()) == 0:
        raise ValueError("Il file scaricato e vuoto")

    return text


def acquire_source(data):
    """Return (code, source_meta). Raises ValueError on invalid input."""
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
# Ollama interaction
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
    """Best-effort extraction of the first JSON object from a model response."""
    if not text:
        return None
    # Strip markdown code fences if present.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    # Find first balanced { ... } block.
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    candidate = match.group(0)
    try:
        return json.loads(candidate)
    except Exception:
        # Try progressively trimming trailing chars to recover valid JSON.
        for end in range(len(candidate), 0, -1):
            try:
                return json.loads(candidate[:end])
            except Exception:
                continue
    return None


def normalize_host(host):
    """Ensure OLLAMA_HOST is a real URL with an http(s) scheme.

    Users sometimes store the Ollama Cloud API key in OLLAMA_HOST by mistake;
    that value has no scheme and urllib then fails with 'unknown url type'.
    Return a clean base URL, or raise ValueError with a clear message.
    """
    value = (host or "").strip()
    if not value:
        raise ValueError("OLLAMA_HOST non configurato")
    if not re.match(r"^https?://", value, re.I):
        raise ValueError(
            "OLLAMA_HOST deve essere un URL completo (es. https://ollama.com "
            "o http://localhost:11434). Non memorizzare qui la chiave API: "
            "usa OLLAMA_API_KEY per la chiave."
        )
    return value.rstrip("/")


def call_ollama(host, model_tag, prompt, timeout, api_key=None):
    """Call Ollama /api/chat and return the assistant message text."""
    base = normalize_host(host)
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
    req = urllib.request.Request(
        url,
        data=payload,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
    data = json.loads(raw)
    msg = data.get("message") or {}
    content = msg.get("content") or ""
    if not content:
        # Fall back to /api/generate shape just in case.
        content = data.get("response") or ""
    return content


def analyze_with_model(host, model, prompt, timeout, api_key=None):
    """Run one model, returning a structured result dict."""
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
        content = call_ollama(host, model["tag"], prompt, timeout, api_key=api_key)
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
    except ValueError as e:
        out["error"] = f"Configurazione Ollama non valida: {e}"
    except urllib.error.URLError as e:
        out["error"] = f"Connessione a Ollama fallita: {e.reason if hasattr(e, 'reason') else str(e)}"
    except urllib.error.HTTPError as e:
        out["error"] = f"Ollama HTTP {e.code}: {e.reason}"
    except Exception as e:  # noqa: BLE001
        out["error"] = f"Errore analisi modello: {e}"
    return out


# ---------------------------------------------------------------------------
# Comparison aggregation
# ---------------------------------------------------------------------------
def norm_title(title):
    t = title.lower()
    t = re.sub(r"[^a-z0-9]+", " ", t).strip()
    return t


def sev_score(sev):
    return SEVERITY_SCORE.get(str(sev).lower(), 1)


def build_comparison(model_results):
    """Aggregate findings across models into common / unique / overall risk."""
    # Map normalized title -> aggregate record.
    groups = {}
    for m in model_results:
        if not m.get("ok"):
            continue
        model_name = m["name"]
        seen = set()
        for f in m.get("findings", []):
            key = norm_title(f["title"]) or f["title"].lower()
            if not key:
                continue
            g = groups.get(key)
            if g is None:
                g = {
                    "title": f["title"],
                    "normalized": key,
                    "models": [],
                    "max_severity": "info",
                    "max_score": 0,
                    "categories": set(),
                    "descriptions": [],
                    "recommendations": [],
                }
                groups[key] = g
            if model_name not in g["models"]:
                g["models"].append(model_name)
            if sev_score(f["severity"]) > g["max_score"]:
                g["max_score"] = sev_score(f["severity"])
                g["max_severity"] = f["severity"]
            if f.get("category"):
                g["categories"].add(f["category"])
            if f.get("description"):
                g["descriptions"].append({"model": model_name, "text": f["description"]})
            if f.get("recommendation"):
                g["recommendations"].append({"model": model_name, "text": f["recommendation"]})

    common = []
    unique = []
    for key, g in groups.items():
        entry = {
            "title": g["title"],
            "severity": g["max_severity"],
            "severity_label": SEVERITY_LABEL_IT.get(g["max_severity"], g["max_severity"]),
            "category": ", ".join(sorted(c for c in g["categories"] if c)) or "Generale",
            "models": list(g["models"]),
            "agreement": len(g["models"]),
            "description": (g["descriptions"][0]["text"] if g["descriptions"] else ""),
            "descriptions": g["descriptions"],
            "recommendations": g["recommendations"],
        }
        if len(g["models"]) >= 2:
            common.append(entry)
        else:
            entry["model"] = g["models"][0] if g["models"] else ""
            unique.append(entry)

    common.sort(key=lambda x: sev_score(x["severity"]), reverse=True)
    unique.sort(key=lambda x: sev_score(x["severity"]), reverse=True)

    # Overall risk: weigh common findings more, then unique high severity.
    common_max = max([sev_score(c["severity"]) for c in common], default=0)
    unique_max = max([sev_score(u["severity"]) for u in unique], default=0)
    effective = max(common_max, unique_max if unique_max >= 4 else 0, common_max)

    # If no common but several unique medium, downgrade to Medio/Basso.
    if common_max == 0 and unique_max >= 4:
        effective = 4
    elif common_max == 0 and unique_max == 3:
        effective = 3
    elif effective == 0:
        effective = unique_max

    risk_label = "Nessuno"
    for sev, score in sorted(SEVERITY_SCORE.items(), key=lambda x: x[1], reverse=True):
        if effective >= score and score > 0:
            risk_label = SEVERITY_LABEL_IT.get(sev, sev)
            break

    # Build a conclusive summary.
    total_findings = sum(len(m.get("findings", [])) for m in model_results if m.get("ok"))
    models_ok = [m["name"] for m in model_results if m.get("ok")]
    models_failed = [m["name"] for m in model_results if not m.get("ok")]

    summary_parts = []
    summary_parts.append(
        f"Analisi completata con {len(models_ok)}/{len(model_results)} modelli attivi."
    )
    summary_parts.append(f"Trovate {total_findings} vulnerabilita totali segnalate.")
    summary_parts.append(f"{len(common)} vulnerabilita individuate da piu modelli (concordanti).")
    summary_parts.append(f"{len(unique)} vulnerabilita segnalate da un solo modello.")
    if models_failed:
        summary_parts.append(
            f"Modelli non disponibili: {', '.join(models_failed)}."
        )
    summary_parts.append(f"Livello di rischio complessivo stimato: {risk_label}.")

    return {
        "common": common,
        "unique": unique,
        "overall_risk": risk_label,
        "overall_score": effective,
        "summary": " ".join(summary_parts),
        "models_ok": models_ok,
        "models_failed": models_failed,
    }


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------
def main(args, ctx=None):
    method = request_method(args)
    if method == "GET":
        return {
            "ok": True,
            "service": "securitycheck",
            "models": [m["name"] for m in MODELS],
            "description": "Analisi di sicurezza del codice sorgente con 3 modelli Ollama in parallelo.",
        }

    # ctx.OLLAMA_HOST is injected by the generated wrapper; when empty the
    # wrapper raises "Required secret OLLAMA_HOST is not configured" (fail closed).
    host = getattr(ctx, "OLLAMA_HOST", None) if ctx else None
    if not host:
        return {
            "ok": False,
            "error": "Ollama non configurato. Imposta OLLAMA_HOST nel file .env e ridistribuisci.",
        }
    try:
        normalize_host(host)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    # Optional Bearer token for remote/cloud Ollama (e.g. https://ollama.com).
    api_key = getattr(ctx, "OLLAMA_API_KEY", None) if ctx else None

    timeout = DEFAULT_TIMEOUT
    # Optional override only if a numeric value is supplied in the request.
    data = request_data(args)
    req_timeout = data.get("timeout")
    if req_timeout:
        try:
            timeout = max(30, min(int(req_timeout), 600))
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

    # Run all three models in parallel.
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(MODELS)) as pool:
        futures = {
            pool.submit(analyze_with_model, host, m, prompt, timeout, api_key=api_key): m
            for m in MODELS
        }
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    # Restore a stable display order matching MODELS.
    order = {m["id"]: i for i, m in enumerate(MODELS)}
    results.sort(key=lambda r: order.get(r["id"], 99))

    comparison = build_comparison(results)

    return {
        "ok": True,
        "source": meta,
        "models": results,
        "comparison": comparison,
    }