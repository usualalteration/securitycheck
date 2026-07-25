import { useEffect, useState, FormEvent, useRef } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Link2,
  Code2,
  Loader2,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Github,
  Cpu,
  Gauge,
  ListChecks,
  RotateCcw,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  analyzeWithModel,
  getServiceInfo,
  MODELS,
  type AnalyzeModelResponse,
  type AnalyzeRequest,
  type Finding,
  type ModelResult,
  type Severity,
  type SourceMeta,
} from "@/lib/security";
import { buildComparison, type Comparison } from "@/lib/compare";

type Mode = "url" | "code";
type SectionPhase = "idle" | "analyzing" | "streaming" | "done" | "failed";

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

function GroupedFindingCard({ g, isCommon }: { g: Comparison["common"][number]; isCommon: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={g.severity} />
        {g.category && (
          <span className="rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
            {g.category}
          </span>
        )}
        {isCommon ? (
          <span className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2 py-0.5 text-xs font-semibold text-primary">
            <ListChecks className="h-3.5 w-3.5" />
            Concordante ({g.agreement}/{g.models.length} modelli)
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-md bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
            Solo {g.model}
          </span>
        )}
      </div>
      <h4 className="mt-2 font-semibold text-foreground">{g.title}</h4>
      {g.description && <p className="mt-1 text-sm text-muted-foreground">{g.description}</p>}
      <div className="mt-2 flex flex-wrap gap-1.5">
        {g.models.map((m) => (
          <span key={m} className="rounded-md bg-muted px-2 py-0.5 text-xs text-muted-foreground">
            {m}
          </span>
        ))}
      </div>
      {isCommon && g.recommendations && g.recommendations.length > 0 && (
        <div className="mt-2">
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
          >
            {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            {open ? "Nascondi" : "Mostra"} raccomandazioni
          </button>
          {open && (
            <ul className="mt-1.5 space-y-1.5">
              {g.recommendations.map((r, i) => (
                <li key={i} className="rounded-md bg-emerald-50 p-2 text-sm text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200">
                  <span className="font-semibold">{r.model}:</span> {r.text}
                </li>
              ))}
            </ul>
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
  index,
  onResult,
  onSource,
}: {
  model: { id: string; name: string };
  req: AnalyzeRequest;
  index: number;
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
        res = await analyzeWithModel({ ...req, model: model.id }, controller.signal);
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
            <h3 className="font-semibold text-foreground">
              <span className="mr-2 text-muted-foreground/60">#{index + 1}</span>
              {model.name}
            </h3>
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

const Index = () => {
  const [mode, setMode] = useState<Mode>("url");
  const [url, setUrl] = useState("");
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [language, setLanguage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [available, setAvailable] = useState<string[] | null>(null);

  const [request, setRequest] = useState<AnalyzeRequest | null>(null);
  const [results, setResults] = useState<Record<string, ModelResult | null>>({});
  const [source, setSource] = useState<SourceMeta | null>(null);

  useEffect(() => {
    getServiceInfo().then((info) => {
      if (info?.models) setAvailable(info.models);
    });
  }, []);

  function reset() {
    setError(null);
    setRequest(null);
    setResults({});
    setSource(null);
    setUrl("");
    setCode("");
    setFilename("");
    setLanguage("");
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

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

    setResults({});
    setSource(null);
    setRequest(baseReq);
  }

  function handleResult(id: string, result: ModelResult | null) {
    setResults((prev) => ({ ...prev, [id]: result }));
  }

  function handleSource(s: SourceMeta) {
    setSource((prev) => prev ?? s);
  }

  const resultsList = MODELS.map((m) => results[m.id]).filter((r): r is ModelResult => r != null);
  const comparison: Comparison | null =
    resultsList.length > 0 ? buildComparison(resultsList) : null;
  const showResults = request !== null;

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
              <p className="text-xs text-muted-foreground">Analisi sicurezza codice multi-modello</p>
            </div>
          </div>
          {available && available.length > 0 && (
            <div className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex">
              <Cpu className="h-3.5 w-3.5" />
              {available.join(" · ")}
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
                Avrai tre sezioni, una per modello, ognuna con il suo pulsante
                "Analizza con": l'analisi parte su richiesta e il risultato viene
                streammato man mano che si forma.
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
                  Modelli: GLM 5.2 · Kimi K2.7 Code · DeepSeek V4 Pro (via Ollama)
                </p>
                <Button type="submit" size="lg" className="gap-2">
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

        {showResults && request && (
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
              Ogni sezione ha il suo pulsante "Analizza con". Premi quello del modello
              che vuoi usare: ha 3 minuti per collegarsi; se non riesce, riprova fino
              a 4 volte (5 tentativi in tutto) con 3 secondi di pausa. Il report viene
              streammato e rilasciato man mano che si forma. Se il modello resta non
              disponibile, il pulsante mostra "<strong>riprova</strong>".
            </p>

            {/* Per-model sections, each with its own "Analizza con" button */}
            <section>
              <div className="mb-3 flex items-center gap-2">
                <Cpu className="h-5 w-5 text-primary" />
                <h3 className="text-lg font-semibold text-foreground">Report per modello</h3>
              </div>
              <div className="grid gap-4 lg:grid-cols-3">
                {MODELS.map((m, i) => (
                  <ModelSection
                    key={m.id}
                    model={m}
                    req={request}
                    index={i}
                    onResult={handleResult}
                    onSource={handleSource}
                  />
                ))}
              </div>
            </section>

            {/* Comparison / overall risk (live, once at least one model produced a result) */}
            {comparison && (
              <>
                <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
                  <div className="flex items-center gap-2">
                    <Gauge className="h-5 w-5 text-primary" />
                    <h3 className="text-lg font-semibold text-foreground">Confronto e riepilogo</h3>
                  </div>
                  <p className="mt-3 text-sm text-muted-foreground">{comparison.summary}</p>

                  <div className="mt-4 flex flex-wrap items-center gap-4">
                    <div className="text-right">
                      <p className="text-xs text-muted-foreground">Rischio complessivo</p>
                      <RiskBadge risk={comparison.overall_risk} />
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-muted-foreground">Modelli attivi</p>
                      <p className="font-bold text-foreground">
                        {comparison.models_ok.length}/{MODELS.length}
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 grid gap-3 sm:grid-cols-3">
                    <div className="rounded-lg border border-border bg-muted/40 p-4 text-center">
                      <p className="text-2xl font-bold text-foreground">{comparison.common.length}</p>
                      <p className="text-xs text-muted-foreground">Vulnerabilita comuni (concordanti)</p>
                    </div>
                    <div className="rounded-lg border border-border bg-muted/40 p-4 text-center">
                      <p className="text-2xl font-bold text-foreground">{comparison.unique.length}</p>
                      <p className="text-xs text-muted-foreground">Segnalate da un solo modello</p>
                    </div>
                    <div className="rounded-lg border border-border bg-muted/40 p-4 text-center">
                      <p className="text-2xl font-bold text-foreground">
                        {comparison.models_ok.length}/{MODELS.length}
                      </p>
                      <p className="text-xs text-muted-foreground">Modelli attivi</p>
                    </div>
                  </div>

                  {comparison.models_failed.length > 0 && (
                    <div className="mt-4 flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                      <span>
                        Modelli non disponibili: {comparison.models_failed.join(", ")}. Usa il
                        pulsante "riprova" di ciascuna sezione.
                      </span>
                    </div>
                  )}
                </section>

                {/* Common vulnerabilities */}
                {comparison.common.length > 0 && (
                  <section>
                    <div className="mb-3 flex items-center gap-2">
                      <ListChecks className="h-5 w-5 text-primary" />
                      <h3 className="text-lg font-semibold text-foreground">
                        Vulnerabilita comuni ({comparison.common.length})
                      </h3>
                    </div>
                    <div className="grid gap-3 lg:grid-cols-2">
                      {comparison.common.map((g, i) => (
                        <GroupedFindingCard key={i} g={g} isCommon />
                      ))}
                    </div>
                  </section>
                )}

                {/* Unique vulnerabilities */}
                {comparison.unique.length > 0 && (
                  <section>
                    <div className="mb-3 flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-amber-500" />
                      <h3 className="text-lg font-semibold text-foreground">
                        Segnalate solo da alcuni modelli ({comparison.unique.length})
                      </h3>
                    </div>
                    <div className="grid gap-3 lg:grid-cols-2">
                      {comparison.unique.map((g, i) => (
                        <GroupedFindingCard key={i} g={g} isCommon={false} />
                      ))}
                    </div>
                  </section>
                )}
              </>
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-border py-6 text-center text-xs text-muted-foreground/70">
        SecurityCheck · analisi sicurezza codice multi-modello via Ollama
      </footer>
    </div>
  );
};

export default Index;