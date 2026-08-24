// Client for the OpenServerless actions (v1/models discovery + v1/analyze-model).

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "none";

export interface SourceMeta {
  type: "url" | "code";
  url?: string | null;
  filename?: string | null;
  language?: string;
  size?: number;
  lines?: number;
}

export interface Finding {
  title: string;
  severity: Severity;
  category?: string;
  description?: string;
  line?: string | number | null;
  recommendation?: string;
}

export interface ModelResult {
  id: string;
  name: string;
  ok: boolean;
  risk_level: Severity;
  summary: string;
  findings: Finding[];
  report: string;
  error: string | null;
}

/**
 * A model discovered dynamically from the provider's model-listing API.
 * The id is the exact value sent back to the inference action; `name` is a
 * friendly label (defaults to the id when the provider gives no name).
 */
export interface DiscoveredModel {
  id: string;
  name: string;
  provider?: string;
  object?: string;
  type?: string;
  capabilities?: string[];
  raw?: Record<string, unknown>;
}

/** Provider protocol detected by the backend discovery service. */
export type ModelProtocol =
  | "openai-compatible"
  | "ollama"
  | "anthropic"
  | "gemini";

export type ModelsErrorType =
  | "auth"
  | "network"
  | "api"
  | "config"
  | "empty"
  | "method";

export interface ModelsResponse {
  ok: boolean;
  models?: DiscoveredModel[];
  default?: string | null;
  source?: string;
  provider?: string;
  protocol?: ModelProtocol;
  endpoint?: string;
  count?: number;
  error?: string;
  error_type?: ModelsErrorType;
  endpoints?: string[];
}

export interface AnalyzeRequest {
  url?: string;
  code?: string;
  filename?: string;
  language?: string;
}

export interface ModelAnalyzeRequest extends AnalyzeRequest {
  model: string;
  model_name?: string;
  /** Backend-derived protocol hint from v1/models; enables provider-aware
   * inference routing. Optional: the backend re-detects if absent. */
  protocol?: ModelProtocol;
}

export interface AnalyzeModelResponse {
  ok: boolean;
  error?: string;
  source?: SourceMeta;
  model?: ModelResult;
}

export interface ServiceInfo {
  ok: boolean;
  service?: string;
  models_endpoint?: string;
  model_endpoint?: string;
  description?: string;
}

async function unwrap<T>(response: Response): Promise<T> {
  const raw = await response.json().catch(() => ({} as Record<string, unknown>));
  const obj =
    raw && typeof raw === "object" && "body" in raw && typeof (raw as Record<string, unknown>).body === "object"
      ? ((raw as Record<string, unknown>).body as T)
      : (raw as T);
  return obj as T;
}

/**
 * Discover the text/code-generation models accessible with the configured
 * server-side API key. The key never reaches the browser: the backend
 * v1/models action performs the call and returns only the model catalog.
 */
export async function fetchModels(signal?: AbortSignal): Promise<ModelsResponse> {
  let response: Response;
  try {
    response = await fetch("/api/my/v1/models", { method: "GET", signal });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    return {
      ok: false,
      error: "Errore di rete durante il recupero dei modelli.",
      error_type: "network",
      models: [],
    };
  }

  const data = await unwrap<ModelsResponse>(response);

  if (!response.ok || data?.ok === false || data?.error) {
    if (response.status === 401 || response.status === 403) {
      return {
        ok: false,
        error: data?.error || "Autenticazione API fallita. Verifica la chiave API configurata.",
        error_type: data?.error_type || "auth",
        models: [],
      };
    }
    return {
      ok: false,
      error: data?.error || `Recupero modelli fallito: ${response.status}`,
      error_type: data?.error_type || "api",
      models: [],
    };
  }
  return data;
}

/**
 * Analyze source code with the user-selected model, single attempt.
 * The backend gives the model up to 3 minutes (180s) to connect/respond.
 * The retry loop lives in the UI: 1 attempt + 4 retries with 3s pauses
 * (5 total); after 5 failures the model button shows "riprova".
 * Pass an AbortSignal to enforce the 180s per-attempt timeout client-side.
 */
export async function analyzeWithModel(
  req: ModelAnalyzeRequest,
  signal?: AbortSignal,
): Promise<AnalyzeModelResponse> {
  const response = await fetch("/api/my/v1/analyze-model", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
    signal,
  });

  const data = await unwrap<AnalyzeModelResponse>(response);

  if (!response.ok || data?.ok === false || data?.error) {
    const message =
      data?.error ||
      (response.status === 500
        ? "Provider AI non configurato. Imposta AI_BASE_URL nel file .env e ridistribuisci."
        : `Richiesta fallita: ${response.status}`);
    return { ok: false, error: message };
  }
  return data;
}

export async function getServiceInfo(): Promise<ServiceInfo | null> {
  try {
    const response = await fetch("/api/my/v1/analyze", { method: "GET" });
    const data = await unwrap<ServiceInfo>(response);
    if (data && data.service) return data;
    return null;
  } catch {
    return null;
  }
}

/**
 * Build the display label for a discovered model.
 * Shows "FriendlyName — model-id" when a distinct friendly name is available,
 * otherwise "model-id — Provider" when the provider brand is known, else just
 * the model id. The dropdown value always remains the exact provider id.
 */
export function modelLabel(m: DiscoveredModel): string {
  const name = (m.name || "").trim();
  const id = m.id;
  const provider = (m.provider || "").trim();
  if (name && name !== id) return `${name} — ${id}`;
  if (provider && provider.toLowerCase() !== "custom") return `${id} — ${provider}`;
  return id;
}

/** Human-readable protocol label for the detected provider protocol. */
export function protocolLabel(p?: ModelProtocol): string {
  switch (p) {
    case "openai-compatible":
      return "OpenAI-compatible";
    case "ollama":
      return "Ollama API";
    case "anthropic":
      return "Anthropic Messages";
    case "gemini":
      return "Gemini generateContent";
    default:
      return "—";
  }
}