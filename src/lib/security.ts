// Client for the v1/analyze OpenServerless action.

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

export interface Comparison {
  common: GroupedFinding[];
  unique: GroupedFinding[];
  overall_risk: string;
  overall_score: number;
  summary: string;
  models_ok: string[];
  models_failed: string[];
}

export interface AnalyzeResponse {
  ok: boolean;
  error?: string;
  source?: SourceMeta;
  models?: ModelResult[];
  comparison?: Comparison;
  service?: string;
  description?: string;
}

export interface AnalyzeRequest {
  url?: string;
  code?: string;
  filename?: string;
  language?: string;
}

async function unwrap(response: Response): Promise<AnalyzeResponse> {
  const raw = await response.json().catch(() => ({} as Record<string, unknown>));
  const data =
    raw && typeof raw === "object" && "body" in raw && typeof (raw as Record<string, unknown>).body === "object"
      ? ((raw as Record<string, unknown>).body as AnalyzeResponse)
      : (raw as AnalyzeResponse);
  return data as AnalyzeResponse;
}

export async function analyzeCode(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  const response = await fetch("/api/my/v1/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });

  const data = await unwrap(response);

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

export async function getServiceInfo(): Promise<AnalyzeResponse | null> {
  try {
    const response = await fetch("/api/my/v1/analyze", { method: "GET" });
    const data = (await unwrap(response)) as AnalyzeResponse;
    if (data && data.service) return data;
    return null;
  } catch {
    return null;
  }
}