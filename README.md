# SecurityCheck

Web application per l'**analisi automatica della sicurezza del codice sorgente** con tre
modelli AI eseguiti in parallelo tramite [Ollama](https://ollama.com).

Frontend in React + TypeScript, backend serverless su **Apache OpenWhisk / Nuvolaris**
(action `v1/analyze`).

## Come funziona

1. L'utente sceglie una modalità: **URL di un file** (Raw GitHub / Gist) oppure
   **incolla il codice** in un'area di testo.
2. Se viene fornito un URL, il backend scarica e valida il contenuto; se viene
   incollato il codice, viene usato direttamente.
3. Il codice è inviato **in parallelo** a tre modelli Ollama:
   - [GLM 5.2](https://ollama.com/library/glm-5.2)
   - [Kimi K2.7 Code](https://ollama.com/library/kimi-k2.7-code)
   - [DeepSeek V4 Pro](https://ollama.com/library/deepseek-v4-pro)
4. Ogni modello restituisce un report strutturato con vulnerabilità, severità,
   descrizione e raccomandazione.
5. L'app mostra i **report separati per modello** e un **confronto finale** che
   evidenzia:
   - vulnerabilità **comuni** (concordanti tra più modelli),
   - vulnerabilità **segnalate da un solo modello**,
   - **livello di rischio complessivo** e riepilogo conclusivo.

## Configurazione di Ollama

Nel file `.env` sono presenti le variabili per Ollama:

```env
# Base URL dell'istanza Ollama
#  - locale:   http://localhost:11434
#  - cloud:    https://ollama.com  (richiede OLLAMA_API_KEY)
OLLAMA_HOST=

# Obbligatoria solo per Ollama Cloud (https://ollama.com)
# lascia vuota se usi un'istanza locale senza autenticazione
OLLAMA_API_KEY=
```

Per attivare l'analisi:

1. Avvia Ollama (`ollama serve`) oppure usa Ollama Cloud.
2. Assicurati che i modelli richiesti siano disponibili:
   - `glm-5.2`
   - `kimi-k2.7-code`
   - `deepseek-v4-pro`
   (con Ollama locale: `ollama pull glm-5.2` ecc.)
3. Imposta `OLLAMA_HOST` (e `OLLAMA_API_KEY` per il cloud) nel file `.env`.
4. Ridistribuisci:
   ```bash
   timeout 120 ops ide deploy
   ```

Se `OLLAMA_HOST` (o `OLLAMA_API_KEY` per il cloud) resta vuoto, l'action
fallisce in modo controllato segnalando "Required secret ... is not configured".

## Architettura del backend

- `v1/analyze` (GET): endpoint informativo (elenca i modelli disponibili).
- `v1/analyze-model` (POST): analizza il sorgente con **un solo modello**.
  Il frontend la chiama **una volta per modello, sequenzialmente** (uno dopo
  l'altro), così Ollama non va in contenzione e ogni modello ha a disposizione
  tutto il tempo necessario (timeout action di 5 minuti per ciascun modello).
  L'action ritenta automaticamente sugli errori transienti `503 / 429 / "response
  not yet ready"` con backoff, per tollerare il caricamento dei modelli.

## Sviluppo

- Frontend: `src/` (React + Tailwind). Pagina principale: `src/pages/Index.tsx`.
- Client API: `src/lib/security.ts`, aggregazione confronto: `src/lib/compare.ts`.
- Backend: `packages/v1/analyze/analyze.py` (info, modificabile) e
  `packages/v1/analyze-model/analyze_model.py` (analisi singolo modello,
  modificabile). I `__main__.py` sono wrapper generati, non modificare.
- Endpoint: `GET /api/my/v1/analyze` (info) e
  `POST /api/my/v1/analyze-model` con body `{ url | code, model, filename?, language? }`.

- [Code Security Checker](code-security-checker.md)
