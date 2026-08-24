# SecurityCheck

Web application for **automated source code security analysis**. The user picks
**one AI model at a time** from a catalog discovered at runtime from the
configured provider, and gets back a structured vulnerability report.

React + TypeScript frontend, serverless backend on **Apache OpenWhisk /
Nuvolaris** (`v1/models` + `v1/analyze-model`).

The app is **provider-agnostic**: no model list is hardcoded. Point it at any
endpoint that speaks one of four protocols and it discovers what is there.

## How it works

1. On load the frontend calls `GET /api/my/v1/models`. The backend probes the
   configured `AI_BASE_URL` with read-only requests, detects the provider
   protocol, and returns the catalog of text/code-generation models plus a
   suggested default. **The API key never reaches the browser** — only the
   action sees it.
2. The user selects a model from the dropdown.
3. The user picks an input mode: **file URL** (Raw GitHub / Gist) or **paste the
   code** into a text area.
4. On submit the frontend `POST`s `/api/my/v1/analyze-model` with the selected
   model id. If a URL was given, the backend downloads and validates the
   content; pasted code is used directly.
5. The backend routes one inference call to the detected protocol and returns a
   structured report: overall risk level, summary, and a list of findings with
   title, severity, category, line, description and recommendation.
6. The UI streams the report in and reveals the findings one by one.

Only one model runs per analysis. To compare models, run the analysis again
with a different one selected.

### Supported protocols

The protocol is auto-detected — the hostname only chooses the probe *order*, the
response shape decides. Unknown hosts are probed safely with read-only `GET`s.

| Protocol | Discovery | Inference | Auth |
|---|---|---|---|
| OpenAI-compatible | `GET {base}/models` | `POST {base}/chat/completions` | `Bearer` |
| Anthropic | `GET {base}/models` | `POST {base}/messages` | `x-api-key` |
| Google Gemini | `GET {base}/models` | `POST {base}/models/{model}:generateContent` | `?key=` |
| Ollama | `GET {base}/api/tags` | `POST {base}/api/chat` | `Bearer` (optional) |

Model ids are used **verbatim** as the provider returns them; they are never
rewritten.

## Configuration

Two variables in `.env`:

```env
# Base URL of the AI provider. Examples:
#  - local Ollama:      http://localhost:11434
#  - Ollama Cloud:      https://ollama.com          (requires AI_API_KEY)
#  - OpenAI-compatible: https://api.openai.com/v1   (requires AI_API_KEY)
AI_BASE_URL=

# Required by providers that authenticate requests.
# Leave empty for a local instance without authentication.
AI_API_KEY=
```

Then redeploy:

```bash
timeout 120 ops ide deploy
```

With a local Ollama, start it (`ollama serve`) and pull at least one model
(`ollama pull <model>`) — the dropdown lists whatever `ollama list` reports.

If `AI_BASE_URL` is empty, both actions fail gracefully with
"Provider AI non configurato. Imposta AI_BASE_URL nel file `.env` e ridistribuisci."
`AI_API_KEY` may stay empty: it is required by the provider, not by the actions.
The key is never included in any response, log, error message, or reported
endpoint.

## Backend architecture

- **`v1/models` (GET)** — provider-agnostic model discovery. Probes the
  adapters in host-hinted order, normalizes the result, filters out non-chat
  models (embeddings, TTS, vision-only, …) and picks a default. Returns
  `{ok, models, default, provider, protocol, endpoint, count}`.
- **`v1/analyze-model` (POST)** — analyses the source with **a single model**.
  Body: `{ url | code, model, model_name?, protocol?, filename?, language? }`.
  The `protocol` hint comes from `v1/models`; without it the backend re-detects
  it. One inference attempt per invocation, bounded by a 180s timeout.
- **`v1/analyze` (GET)** — service descriptor only. It no longer performs any
  analysis and no longer hardcodes a model list; it just points at the two
  endpoints above.

### Retries and timeouts

The retry loop lives in the **frontend**: 1 attempt + 4 retries with 3-second
pauses (5 total), each bounded client-side by a 3-minute `AbortController` that
matches the backend's 180s timeout. After 5 failures the model section shows a
"riprova" button. The backend classifies transient failures (`429`, `500`,
`502`, `503`, `504`, and "loading model" / "not yet ready" / "busy" responses)
so a model that is still warming up is retried rather than reported as broken.

### Input limits

- Downloaded source: max 1 MB.
- Analysed source: max 512 KB.

## Development

- Frontend: `src/` (React + Tailwind). Main page: `src/pages/Index.tsx`.
- API client: `src/lib/security.ts`.
- Backend: `packages/v1/models/models.py` (discovery) and
  `packages/v1/analyze-model/analyze_model.py` (single-model analysis);
  `packages/v1/analyze/analyze.py` is the info endpoint. All three are editable.
  The `__main__.py` files are generated wrappers — do not edit them.

- [Code Security Checker](code-security-checker.md)
