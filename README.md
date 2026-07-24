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

Nel file `.env` è presente la variabile **vuota** `OLLAMA_HOST`, pronta per essere
compilata:

```env
# Base URL della tua istanza Ollama, es. http://localhost:11434
OLLAMA_HOST=
```

Per attivare l'analisi:

1. Installa e avvia Ollama (`ollama serve`).
2. Scarica i modelli richiesti:
   ```bash
   ollama pull glm-5.2
   ollama pull kimi-k2.7-code
   ollama pull deepseek-v4-pro
   ```
3. Imposta `OLLAMA_HOST` nel file `.env` (es. `OLLAMA_HOST=http://localhost:11434`).
4. Ridistribuisci:
   ```bash
   timeout 120 ops ide deploy
   ```

Se `OLLAMA_HOST` resta vuoto, l'action `v1/analyze` fallisce in modo controllato
restituendo l'errore "Required secret OLLAMA_HOST is not configured".

## Sviluppo

- Frontend: `src/` (React + Tailwind). Pagina principale: `src/pages/Index.tsx`.
- Client API: `src/lib/security.ts`.
- Backend: `packages/v1/analyze/analyze.py` (logica modificabile),
  `packages/v1/analyze/__main__.py` (wrapper generato, non modificare).
- Endpoint pubblico: `POST /api/my/v1/analyze` con body JSON `{ url | code, filename?, language? }`.