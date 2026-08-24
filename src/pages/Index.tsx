import { useEffect, useState, FormEvent, useRef, useCallback } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Link2,
  Code2,
  Loader2,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Github,
  Cpu,
  Gauge,
  RotateCcw,
  RefreshCw,
  KeyRound,
  WifiOff,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  analyzeWithModel,
  fetchModels,
  modelLabel,
  protocolLabel,
  getServiceInfo,
  type AnalyzeModelResponse,
  type AnalyzeRequest,
  type DiscoveredModel,
  type Finding,
  type ModelProtocol,
  type ModelResult,
  type ModelsErrorType,
  type ModelsResponse,
  type Severity,
  type SourceMeta,
} from "@/lib/security";

type Mode = "url" | "code";
type SectionPhase = "idle" | "analyzing" | "streaming" | "done" | "failed";
type ModelsState = "idle" | "loading" | "ready" | "error" | "empty";

const SEVERITY_STYLES: Record<Severity, { badge: string; dot: string; label: string }> = {
  critical: { badge: "bg-red-100 text-red-800 border-red-300 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800", dot: "bg-red-500", label: "Critico" },
  high: { badge: "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/60 dark:text-orange-300 dark:border-orange-800", dot: "bg-orange-500", label: "Alto" },
  medium: { badge: "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800", dot: "bg-amber-500", label: "Medio" },
  low: { badge: "bg-sky-100 text-sky-800 border-sky-300 dark:bg-sky-950/60 dark:text-sky-300 dark:border-sky-800", dot: "bg-sky-500", label: "Basso" },
  info: { badge: "bg-slate-100 text-slate-700 border-slate-300 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700", dot: "bg-slate-400", label: "Info" },
  none: { badge: "bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800", dot: "bg-emerald-500", label: "Nessuno" },
};

function riskToSeverity(risk: string): Severity {
  const v = (risk || "").toLowerCase();
  if (v.includes("crit")) return "critical";
  if (v.includes("alt")) return "high";
  if (v.includes("medi")) return "medium";
  if (v.includes("bass")) return "low";
  if (v.includes("info")) return "info";
  return "none";
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${s.badge}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

function RiskBadge({ risk }: { risk: string }) {
  const sev = riskToSeverity(risk);
  const s = SEVERITY_STYLES[sev];
  const Icon = sev === "none" ? ShieldCheck : ShieldAlert;
  return (
    <span className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-bold ${s.badge}`}>
      <Icon className="h-4 w-4" />
      {risk || "Nessuno"}
    </span>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            {finding.category && (
              <span className="rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
                {finding.category}
              </span>
            )}
          </div>
          <h4 className="mt-2 font-semibold text-foreground">{finding.title}</h4>
          {finding.line != null && String(finding.line).trim() !== "" && (
            <p className="mt-0.5 text-xs text-muted-foreground">Riga/e: {String(finding.line)}</p>
          )}
        </div>
      </div>
      {finding.description && (
        <p className="mt-2 text-sm text-muted-foreground">{finding.description}</p>
      )}
      {finding.recommendation && (
        <div className="mt-2">
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
          >
            {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            {open ? "Nascondi" : "Mostra"} raccomandazione
          </button>
          {open && (
            <p className="mt-1.5 rounded-md bg-emerald-50 p-2.5 text-sm text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200">
              {finding.recommendation}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Build a human-readable report in MARKDOWN format from a parsed
 * ModelResult. This is what gets streamed out progressively as the analysis
 * "forms"; it is rendered as live markdown, not a raw terminal box.
 */
function formatReadableReport(m: ModelResult): string {
  const sevLabel = SEVERITY_STYLES[riskToSeverity(m.risk_level)].label;
  const lines: string[] = [];
  lines.push("## Report di sicurezza");
  lines.push("");
  lines.push("| Campo | Valore |");
  lines.push("| --- | --- |");
  lines.push(`| Modello | **${m.name}** |`);
  lines.push(`| Livello di rischio | **${sevLabel}** |`);
  lines.push("");
  lines.push("### Riepilogo");
  lines.push("");
  lines.push(m.summary || "_(nessun riepilogo fornito)_");
  lines.push("");
  const findings = m.findings || [];
  lines.push(`### Segnalazioni (${findings.length})`);
  lines.push("");
  if (findings.length === 0) {
    lines.push("Nessuna vulnerabilita rilevata da questo modello.");
  } else {
    findings.forEach((f, i) => {
      const fSev = SEVERITY_STYLES[riskToSeverity(f.severity)].label;
      lines.push(`#### ${i + 1}. ${f.title}`);
      lines.push("");
      lines.push("| Campo | Valore |");
      lines.push("| --- | --- |");
      lines.push(`| Severita | ${fSev} |`);
      if (f.category) lines.push(`| Categoria | ${f.category} |`);
      if (f.line != null && String(f.line).trim() !== "")
        lines.push(`| Riga/e | ${String(f.line)} |`);
      lines.push("");
      if (f.description) {
        lines.push(f.description);
        lines.push("");
      }
      if (f.recommendation) {
        lines.push(`> **Raccomandazione:** ${f.recommendation}`);
        lines.push("");
      }
      lines.push("---");
      lines.push("");
    });
  }
  return lines.join("\n").replace(/\n{3,}/g, "\n\n");
}

const MAX_ATTEMPTS = 5;          // 1 attempt + 4 retries
const ATTEMPT_TIMEOUT_MS = 180_000; // 3 minutes per attempt
const RETRY_PAUSE_MS = 3000;     // 3 seconds between attempts
const STREAM_CHUNK = 8;          // chars revealed per tick
const STREAM_TICK_MS = 12;       // tick speed for report streaming
const FINDING_REVEAL_MS = 140;   // delay between revealing each finding

/**
 * One model report section with its own "Analizza con <model>" button.
 *
 * Behavior:
 *  - On click: try to connect to the model. Each attempt has 3 minutes to
 *    succeed (client-side AbortController + backend 180s timeout).
 *  - On failure, retry up to 4 more times (5 total) with a 3-second pause
 *    between attempts.
 *  - After 5 total failures, show a "<model> riprova" button.
 *  - When the model responds, the report text is streamed out progressively
 *    (released as it forms) and findings are revealed one by one.
 */
function ModelSection({
  model,
  req,
  protocol,
  onResult,
  onSource,
}: {
  model: { id: string; name: string };
  req: AnalyzeRequest;
  protocol?: ModelProtocol;
  onResult: (id: string, result: ModelResult | null) => void;
  onSource: (s: SourceMeta) => void;
}) {
  const [phase, setPhase] = useState<SectionPhase>("idle");
  const [attempt, setAttempt] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const [result, setResult] = useState<ModelResult | null>(null);
  const [streamedReport, setStreamedReport] = useState("");
  const [revealedFindings, setRevealedFindings] = useState(0);
  const streamTimer = useRef<number | null>(null);

  // Reset everything when the underlying request changes (new analysis).
  useEffect(() => {
    setPhase("idle");
    setAttempt(0);
    setStatusMsg("");
    setResult(null);
    setStreamedReport("");
    setRevealedFindings(0);
    if (streamTimer.current) {
      clearInterval(streamTimer.current);
      streamTimer.current = null;
    }
  }, [req]);

  useEffect(() => () => {
    if (streamTimer.current) clearInterval(streamTimer.current);
  }, []);

  function failedResult(): ModelResult {
    return {
      id: model.id,
      name: model.name,
      ok: false,
      risk_level: "none",
      summary: "",
      findings: [],
      report: "",
      error: "modello non disponibile",
    };
  }

  async function streamResult(m: ModelResult) {
    setPhase("streaming");
    setResult(m);
    setStreamedReport("");
    setRevealedFindings(0);

    // 1) Stream the readable (non-JSON) report progressively, released as it
    //    forms.
    const full = formatReadableReport(m);
    await new Promise<void>((resolve) => {
      let i = 0;
      streamTimer.current = window.setInterval(() => {
        i += STREAM_CHUNK;
        if (i >= full.length) {
          setStreamedReport(full);
          if (streamTimer.current) {
            clearInterval(streamTimer.current);
            streamTimer.current = null;
          }
          resolve();
        } else {
          setStreamedReport(full.slice(0, i));
        }
      }, STREAM_TICK_MS);
    });

    // 2) Reveal the parsed findings one by one.
    for (let k = 0; k < m.findings.length; k++) {
      setRevealedFindings(k + 1);
      await sleep(FINDING_REVEAL_MS);
    }
    setRevealedFindings(m.findings.length);
    setPhase("done");
  }

  async function run() {
    if (phase === "analyzing" || phase === "streaming") return;
    setPhase("analyzing");
    setAttempt(1);
    setStatusMsg("collegamento al modello...");
    setResult(null);
    setStreamedReport("");
    setRevealedFindings(0);
    onResult(model.id, null);

    let lastError = "modello non disponibile";

    for (let a = 1; a <= MAX_ATTEMPTS; a++) {
      setAttempt(a);
      setStatusMsg(
        a === 1
          ? "collegamento al modello (3 min a disposizione)..."
          : `tentativo ${a}/${MAX_ATTEMPTS} - collegamento al modello...`,
      );

      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), ATTEMPT_TIMEOUT_MS);
      let res: AnalyzeModelResponse;
      try {
        res = await analyzeWithModel(
          { ...req, model: model.id, model_name: model.name, protocol },
          controller.signal,
        );
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") {
          res = { ok: false, error: "timeout: il modello non ha risposto in 3 minuti" };
        } else {
          res = { ok: false, error: err instanceof Error ? err.message : "errore di rete" };
        }
      } finally {
        window.clearTimeout(timer);
      }

      if (res.ok && res.model) {
        if (res.source) onSource(res.source);
        onResult(model.id, res.model);
        await streamResult(res.model);
        return;
      }

      lastError = res.error || lastError;
      if (a < MAX_ATTEMPTS) {
        setStatusMsg(`modello non disponibile, riprovo tra 3s... (tentativo ${a}/${MAX_ATTEMPTS} fallito)`);
        await sleep(RETRY_PAUSE_MS);
      }
    }

    // 5 total failures: show the "riprova" button.
    const failed = { ...failedResult(), error: lastError };
    setResult(failed);
    onResult(model.id, failed);
    setPhase("failed");
  }

  const busy = phase === "analyzing" || phase === "streaming";
  const sev = result ? riskToSeverity(result.risk_level) : "none";

  // Button content per phase.
  let buttonLabel: React.ReactNode = `Analizza con ${model.name}`;
  let buttonIcon: React.ReactNode = <Cpu className="h-4 w-4" />;
  let buttonDisabled = busy;
  if (busy) {
    buttonLabel = statusMsg || "analisi in corso...";
    buttonIcon = <Loader2 className="h-4 w-4 animate-spin" />;
  } else if (phase === "done") {
    buttonLabel = `Rianalizza con ${model.name}`;
    buttonIcon = <RotateCcw className="h-4 w-4" />;
  } else if (phase === "failed") {
    buttonLabel = `${model.name} riprova`;
    buttonIcon = <RotateCcw className="h-4 w-4" />;
  }

  return (
    <div className="rounded-xl border border-border bg-card shadow-sm">
      {/* Header: model name + action button */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Cpu className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-semibold text-foreground">{model.name}</h3>
            <p className="text-xs text-muted-foreground">{model.id}</p>
            {phase === "idle" && (
              <span className="text-xs text-muted-foreground">in attesa di analisi</span>
            )}
            {busy && (
              <span className="text-xs text-primary">{statusMsg}</span>
            )}
            {phase === "done" && result && (
              <span className="text-xs text-muted-foreground">
                {result.findings.length} segnalazione/i
              </span>
            )}
            {phase === "failed" && result && (
              <span className="text-xs text-red-500">{result.error}</span>
            )}
          </div>
        </div>
        <Button
          type="button"
          size="sm"
          onClick={run}
          disabled={buttonDisabled}
          variant={phase === "failed" ? "destructive" : "default"}
          className="gap-2"
        >
          {buttonIcon}
          {buttonLabel}
        </Button>
      </div>

      {/* Body: status + streaming report + findings */}
      <div className="space-y-3 p-4">
        {/* Attempt progress while analyzing */}
        {busy && (
          <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
            <div className="flex items-center justify-between text-xs text-foreground">
              <span className="flex items-center gap-2 font-medium">
                <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
                {statusMsg}
              </span>
              {phase === "analyzing" && attempt > 0 && (
                <span className="text-muted-foreground">tentativo {attempt}/{MAX_ATTEMPTS}</span>
              )}
            </div>
            {/* Retry dots */}
            <div className="mt-2 flex items-center gap-1.5">
              {Array.from({ length: MAX_ATTEMPTS }).map((_, i) => {
                const n = i + 1;
                const filled = phase === "analyzing" && n <= attempt;
                return (
                  <span
                    key={n}
                    className={`h-1.5 flex-1 rounded-full ${
                      filled ? "bg-primary" : "bg-muted"
                    }`}
                  />
                );
              })}
            </div>
          </div>
        )}

        {/* Failure banner */}
        {phase === "failed" && result?.error && (
          <div className="flex items-start gap-2 rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>
              {result.error}. Il modello non e risultato disponibile dopo {MAX_ATTEMPTS} tentativi.
              Premi "<strong>{model.name} riprova</strong>" per riprovare.
            </span>
          </div>
        )}

        {/* Streaming / done: summary + risk */}
        {(phase === "streaming" || phase === "done") && result && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              {result.summary && (
                <p className="flex-1 text-sm text-muted-foreground">{result.summary}</p>
              )}
              <RiskBadge risk={SEVERITY_STYLES[sev].label} />
            </div>

            {result.ok && revealedFindings === 0 && result.findings.length === 0 && phase === "done" && (
              <div className="flex items-center gap-2 rounded-md border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200">
                <CheckCircle2 className="h-4 w-4" />
                Nessuna vulnerabilita rilevata da questo modello.
              </div>
            )}
          </>
        )}

        {/* Streaming markdown report, rendered live as it forms */}
        {(phase === "streaming" || phase === "done") && result && (
          <div>
            <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
              {phase === "streaming" ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  report in streaming...
                </>
              ) : (
                <span>report completo</span>
              )}
            </div>
            <div className="max-h-96 overflow-auto rounded-md border border-border bg-muted/30 p-4">
              <div className="prose prose-sm dark:prose-invert max-w-none">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{streamedReport || ""}</ReactMarkdown>
              </div>
              {phase === "streaming" && (
                <span className="mt-2 inline-block h-4 w-2 animate-pulse bg-primary align-middle" />
              )}
            </div>
          </div>
        )}

        {/* Findings revealed one by one during/after streaming */}
        {result && result.ok && revealedFindings > 0 && (
          <div className="space-y-3">
            {result.findings.slice(0, revealedFindings).map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
            {phase === "streaming" && revealedFindings < result.findings.length && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                individuazione segnalazioni... ({revealedFindings}/{result.findings.length})
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Error icon for a given model-discovery error type.
 */
function modelsErrorIcon(type?: ModelsErrorType) {
  if (type === "auth") return <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />;
  if (type === "network") return <WifiOff className="mt-0.5 h-4 w-4 shrink-0" />;
  return <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />;
}

const Index = () => {
  const [mode, setMode] = useState<Mode>("url");
  const [url, setUrl] = useState("");
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [language, setLanguage] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Dynamic model discovery state.
  const [models, setModels] = useState<DiscoveredModel[]>([]);
  const [modelsState, setModelsState] = useState<ModelsState>("idle");
  const [modelsError, setModelsError] = useState<string | null>(null);
  const [modelsErrorType, setModelsErrorType] = useState<ModelsErrorType | undefined>(undefined);
  const [selectedModelId, setSelectedModelId] = useState<string>("");
  const [detectedProvider, setDetectedProvider] = useState<string | null>(null);
  const [detectedProtocol, setDetectedProtocol] = useState<ModelProtocol | undefined>(undefined);
  const modelsAbort = useRef<AbortController | null>(null);

  const [request, setRequest] = useState<AnalyzeRequest | null>(null);
  const [result, setResult] = useState<ModelResult | null>(null);
  const [source, setSource] = useState<SourceMeta | null>(null);

  const loadModels = useCallback(async () => {
    if (modelsAbort.current) modelsAbort.current.abort();
    const controller = new AbortController();
    modelsAbort.current = controller;
    setModelsState("loading");
    setModelsError(null);
    setModelsErrorType(undefined);
    let resp: ModelsResponse;
    try {
      resp = await fetchModels(controller.signal);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setModelsState("error");
      setModelsError("Errore di rete durante il recupero dei modelli.");
      setModelsErrorType("network");
      return;
    }
    if (controller.signal.aborted) return;
    if (!resp.ok) {
      setModels([]);
      setDetectedProvider(null);
      setDetectedProtocol(undefined);
      setModelsError(resp.error || "Impossibile recuperare i modelli.");
      setModelsErrorType(resp.error_type);
      // "empty" is a success-with-no-models state, distinct from an error.
      setModelsState(resp.error_type === "empty" ? "empty" : "error");
      return;
    }
    const list = resp.models || [];
    setModels(list);
    setDetectedProvider(resp.provider || null);
    setDetectedProtocol(resp.protocol);
    setModelsState(list.length > 0 ? "ready" : "empty");
    if (list.length === 0) {
      setModelsError("No compatible models available");
      setModelsErrorType("empty");
      return;
    }
    setModelsError(null);
    setModelsErrorType(undefined);
    // Preserve the current selection if still available; otherwise pick the
    // provider-recommended default, else a sensible default, else the first.
    setSelectedModelId((prev) => {
      if (prev && list.some((m) => m.id === prev)) return prev;
      if (resp.default && list.some((m) => m.id === resp.default)) return resp.default;
      return list[0]?.id ?? "";
    });
  }, []);

  // Discover models on mount.
  useEffect(() => {
    loadModels();
    return () => {
      if (modelsAbort.current) modelsAbort.current.abort();
    };
  }, [loadModels]);

  // Touch the service descriptor once (kept for compatibility) but do not use
  // it for the model list, which is now discovered dynamically via v1/models.
  useEffect(() => {
    getServiceInfo();
  }, []);

  const selectedModel = models.find((m) => m.id === selectedModelId) || null;

  function reset() {
    setError(null);
    setRequest(null);
    setResult(null);
    setSource(null);
    setUrl("");
    setCode("");
    setFilename("");
    setLanguage("");
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (!selectedModelId) {
      setError("Seleziona un modello AI prima di avviare l'analisi.");
      return;
    }
    if (mode === "url" && !url.trim()) {
      setError("Inserisci un URL valido.");
      return;
    }
    if (mode === "code" && !code.trim()) {
      setError("Incolla il codice sorgente da analizzare.");
      return;
    }

    const baseReq: AnalyzeRequest = {
      url: mode === "url" ? url.trim() : undefined,
      code: mode === "code" ? code : undefined,
      filename: filename.trim() || undefined,
      language: language.trim() || undefined,
    };

    setResult(null);
    setSource(null);
    setRequest(baseReq);
  }

  function handleResult(_id: string, res: ModelResult | null) {
    setResult(res);
  }

  function handleSource(s: SourceMeta) {
    setSource((prev) => prev ?? s);
  }

  const showResults = request !== null && selectedModel !== null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-muted">
      {/* Header */}
      <header className="border-b border-border bg-background/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-blue-500 text-white shadow-elegant">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold leading-tight text-foreground">SecurityCheck</h1>
              <p className="text-xs text-muted-foreground">Analisi sicurezza codice con modello AI selezionato</p>
            </div>
          </div>
          {modelsState === "ready" && selectedModel && (
            <div className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex">
              <Cpu className="h-3.5 w-3.5" />
              {modelLabel(selectedModel)}
            </div>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        {!showResults && (
          <div className="mx-auto max-w-3xl">
            <div className="mb-6 text-center">
              <h2 className="text-2xl font-bold text-foreground sm:text-3xl">
                Analisi automatica della sicurezza del codice
              </h2>
              <p className="mt-2 text-muted-foreground">
                Fornisci un file di codice (URL Raw/Gist) oppure incolla il sorgente.
                Seleziona il modello AI da usare dall'elenco dinamico scoperto con la
                tua chiave API, quindi avvia l'analisi. Il risultato viene streammato
                man mano che si forma.
              </p>
            </div>

            {/* Mode selector */}
            <div className="mb-6 grid grid-cols-2 gap-2 rounded-xl border border-border bg-card p-1.5">
              <button
                type="button"
                onClick={() => setMode("url")}
                className={`flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors ${
                  mode === "url"
                    ? "bg-primary text-primary-foreground shadow"
                    : "text-muted-foreground hover:bg-muted"
                }`}
              >
                <Link2 className="h-4 w-4" />
                URL di un file
              </button>
              <button
                type="button"
                onClick={() => setMode("code")}
                className={`flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors ${
                  mode === "code"
                    ? "bg-primary text-primary-foreground shadow"
                    : "text-muted-foreground hover:bg-muted"
                }`}
              >
                <Code2 className="h-4 w-4" />
                Incolla il codice
              </button>
            </div>

            <form onSubmit={onSubmit} className="rounded-xl border border-border bg-card p-6 shadow-sm">
              {/* AI Model selector (dynamic discovery) */}
              <div className="mb-5 space-y-2 rounded-lg border border-border bg-muted/30 p-4">
                <Label htmlFor="ai-model-select">AI Model</Label>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                  <div className="flex-1">
                    {modelsState === "loading" ? (
                      <div className="flex h-9 items-center gap-2 rounded-md border border-input bg-background px-3 text-sm text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Loading models…
                      </div>
                    ) : modelsState === "ready" ? (
                      <select
                        id="ai-model-select"
                        name="ai-model"
                        value={selectedModelId}
                        onChange={(e) => setSelectedModelId(e.target.value)}
                        className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      >
                        {models.map((m) => (
                          <option key={m.id} value={m.id}>
                            {modelLabel(m)}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <div className="flex h-9 items-center rounded-md border border-dashed border-input bg-background px-3 text-sm text-muted-foreground">
                        {modelsState === "empty"
                          ? "No compatible models available"
                          : "Nessun modello caricato"}
                      </div>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={loadModels}
                    disabled={modelsState === "loading"}
                    className="h-9 shrink-0 gap-2"
                  >
                    <RefreshCw className={`h-4 w-4 ${modelsState === "loading" ? "animate-spin" : ""}`} />
                    Refresh models
                  </Button>
                </div>
                {modelsState === "ready" && (detectedProvider || detectedProtocol) && (
                  <p className="text-xs text-muted-foreground">
                    Provider: {detectedProvider || "—"}
                    {detectedProtocol ? ` · Protocol: ${protocolLabel(detectedProtocol)}` : ""}
                  </p>
                )}

                {/* Error / status states */}
                {modelsState === "error" && modelsError && (
                  <div className="mt-3 flex items-start gap-2 rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">
                    {modelsErrorIcon(modelsErrorType)}
                    <span>
                      {modelsErrorType === "auth"
                        ? "Errore di autenticazione API: "
                        : modelsErrorType === "network"
                        ? "Errore di rete: "
                        : ""}
                      {modelsError}
                    </span>
                  </div>
                )}
                {modelsState === "empty" && (
                  <div className="mt-3 flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>
                      No compatible models available per la chiave API configurata.
                      Usa "Refresh models" dopo aver verificato la configurazione.
                    </span>
                  </div>
                )}
              </div>

              {mode === "url" ? (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="url-input">URL del file di codice</Label>
                    <Input
                      id="url-input"
                      name="url"
                      type="url"
                      placeholder="https://raw.githubusercontent.com/user/repo/main/file.py"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      autoComplete="off"
                    />
                    <p className="text-xs text-muted-foreground">
                      Funziona con file Raw di GitHub, GitHub Gist e altri URL di testo pubblico.
                      Il backend scarica e valida il contenuto automaticamente.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="code-input">Codice sorgente</Label>
                  <textarea
                    id="code-input"
                    name="code"
                    rows={14}
                    placeholder="// Incolla qui il codice sorgente da analizzare..."
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                  />
                </div>
              )}

              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="filename-input">Nome file (opzionale)</Label>
                  <Input
                    id="filename-input"
                    name="filename"
                    placeholder="es. auth.py"
                    value={filename}
                    onChange={(e) => setFilename(e.target.value)}
                    autoComplete="off"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="language-input">Linguaggio (opzionale)</Label>
                  <Input
                    id="language-input"
                    name="language"
                    placeholder="auto-rilevato"
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    autoComplete="off"
                  />
                </div>
              </div>

              {error && (
                <div className="mt-4 flex items-start gap-2 rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-xs text-muted-foreground">
                  Modello selezionato:{" "}
                  <span className="font-medium text-foreground">
                    {selectedModel ? modelLabel(selectedModel) : "nessuno"}
                  </span>
                </p>
                <Button
                  type="submit"
                  size="lg"
                  className="gap-2"
                  disabled={modelsState !== "ready" || !selectedModelId}
                >
                  <ShieldCheck className="h-4 w-4" />
                  Prepara l'analisi
                </Button>
              </div>
            </form>

            <div className="mt-4 flex items-center justify-center gap-2 text-xs text-muted-foreground/70">
              <Github className="h-3.5 w-3.5" />
              <span>Analisi eseguita lato backend con Apache OpenWhisk / Nuvolaris</span>
            </div>
          </div>
        )}

        {showResults && request && selectedModel && (
          <div className="space-y-8">
            {/* Top bar: source + reset */}
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <FileCode className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Codice da analizzare</p>
                  <p className="font-semibold text-foreground">
                    {source?.language || (language || "Codice")} ·{" "}
                    {source?.lines ?? "—"} righe ·{" "}
                    {source?.size ?? "—"} byte
                    {source?.type === "url" && source.url ? " · da URL" : " · da input"}
                  </p>
                </div>
              </div>
              <Button variant="outline" onClick={reset} className="gap-2">
                <RotateCcw className="h-4 w-4" />
                Nuova analisi
              </Button>
            </div>

            <p className="text-sm text-muted-foreground">
              Il modello ha 3 minuti per collegarsi; se non risponde, riprova fino
              a 4 volte (5 tentativi in tutto) con 3 secondi di pausa. Il report
              viene streammato e rilasciato man mano che si forma. Se il modello
              resta non disponibile, il pulsante mostra "<strong>riprova</strong>".
            </p>

            {/* Selected-model analysis section */}
            <section>
              <div className="mb-3 flex items-center gap-2">
                <Cpu className="h-5 w-5 text-primary" />
                <h3 className="text-lg font-semibold text-foreground">Report del modello selezionato</h3>
              </div>
              <div className="grid gap-4">
                <ModelSection
                  model={selectedModel}
                  req={request}
                  protocol={detectedProtocol}
                  onResult={handleResult}
                  onSource={handleSource}
                />
              </div>
            </section>

            {/* Overall risk summary (single model) */}
            {result && result.ok && (
              <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
                <div className="flex items-center gap-2">
                  <Gauge className="h-5 w-5 text-primary" />
                  <h3 className="text-lg font-semibold text-foreground">Riepilogo</h3>
                </div>
                <div className="mt-4 flex flex-wrap items-center gap-4">
                  <div className="text-right">
                    <p className="text-xs text-muted-foreground">Rischio complessivo</p>
                    <RiskBadge risk={SEVERITY_STYLES[riskToSeverity(result.risk_level)].label} />
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-muted-foreground">Segnalazioni</p>
                    <p className="font-bold text-foreground">{result.findings.length}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-muted-foreground">Modello</p>
                    <p className="font-bold text-foreground">{result.name}</p>
                  </div>
                </div>
              </section>
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-border py-6 text-center text-xs text-muted-foreground/70">
        SecurityCheck · analisi sicurezza codice con modello AI selezionato dinamicamente
      </footer>
    </div>
  );
};

export default Index;