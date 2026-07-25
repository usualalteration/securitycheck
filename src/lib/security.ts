// Client for the OpenServerless actions (v1/analyze info + v1/analyze-model).

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

export interface GroupedFinding {
  title: string;
  severity: Severity;
  severity_label: string;
  category: string;
  models: string[];
  agreement: number;
  description: string;
  descriptions?: { model: string; text: string }[];
  recommendations?: { model: string; text: string }[];
  model?: string;
}

// Known models, in display order. Must match the backend MODELS dict.
export const MODELS: { id: string; name: string }[] = [
  { id: "glm-5.2", name: "GLM 5.2" },
  { id: "kimi-k2.7-code", name: "Kimi K2.7 Code" },
  { id: "deepseek-v4-pro", name: "DeepSeek V4 Pro" },
];

export interface AnalyzeRequest {
  url?: string;
  code?: string;
  filename?: string;
  language?: string;
}

export interface ModelAnalyzeRequest extends AnalyzeRequest {
  model: string;
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
  models?: string[];
  description?: string;
  model_endpoint?: string;
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
 * Analyze source code with a single model, single attempt.
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
        ? "Ollama non configurato. Imposta OLLAMA_HOST nel file .env e ridistribuisci."
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