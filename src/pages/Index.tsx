import { useEffect, useState, FormEvent } from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  analyzeCode,
  getServiceInfo,
  type AnalyzeResponse,
  type Finding,
  type GroupedFinding,
  type ModelResult,
  type Severity,
} from "@/lib/security";

type Mode = "url" | "code";

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

function FindingCard({ finding, showModel }: { finding: Finding; showModel?: string }) {
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
            {showModel && (
              <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
                {showModel}
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

function ModelReportCard({ result }: { result: ModelResult }) {
  const [showRaw, setShowRaw] = useState(false);
  const sev = riskToSeverity(result.risk_level);
  return (
    <div className="rounded-xl border border-border bg-card shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Cpu className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-semibold text-foreground">{result.name}</h3>
            {result.ok ? (
              <span className="text-xs text-muted-foreground">
                {result.findings.length} segnalazione/i
              </span>
            ) : (
              <span className="text-xs text-red-500">modello non disponibile</span>
            )}
          </div>
        </div>
        {result.ok ? <RiskBadge risk={SEVERITY_STYLES[sev].label} /> : <XCircle className="h-5 w-5 text-red-500" />}
      </div>

      <div className="space-y-3 p-4">
        {result.error && (
          <div className="flex items-start gap-2 rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{result.error}</span>
          </div>
        )}

        {result.ok && result.summary && (
          <p className="text-sm text-muted-foreground">{result.summary}</p>
        )}

        {result.ok && result.findings.length === 0 && !result.error && (
          <div className="flex items-center gap-2 rounded-md border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200">
            <CheckCircle2 className="h-4 w-4" />
            Nessuna vulnerabilità rilevata da questo modello.
          </div>
        )}

        {result.ok && result.findings.length > 0 && (
          <div className="space-y-3">
            {result.findings.map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
          </div>
        )}

        {result.ok && result.report && (
          <div>
            <button
              type="button"
              onClick={() => setShowRaw((s) => !s)}
              className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
            >
              {showRaw ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              {showRaw ? "Nascondi" : "Mostra"} report completo
            </button>
            {showRaw && (
              <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs text-muted-foreground">
                {result.report}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function GroupedFindingCard({ g, isCommon }: { g: GroupedFinding; isCommon: boolean }) {
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

const Index = () => {
  const [mode, setMode] = useState<Mode>("url");
  const [url, setUrl] = useState("");
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("");
  const [language, setLanguage] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [available, setAvailable] = useState<string[] | null>(null);

  // Discover whether the backend is up and which models are configured.
  useEffect(() => {
    getServiceInfo().then((info) => {
      if (info?.models) setAvailable(info.models as unknown as string[]);
    });
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);

    if (mode === "url" && !url.trim()) {
      setError("Inserisci un URL valido.");
      return;
    }
    if (mode === "code" && !code.trim()) {
      setError("Incolla il codice sorgente da analizzare.");
      return;
    }

    setLoading(true);
    try {
      const res = await analyzeCode({
        url: mode === "url" ? url.trim() : undefined,
        code: mode === "code" ? code : undefined,
        filename: filename.trim() || undefined,
        language: language.trim() || undefined,
      });
      if (!res.ok || res.error) {
        setError(res.error || "Analisi non riuscita.");
      } else {
        setResult(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Errore di rete imprevisto.");
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setResult(null);
    setError(null);
    setUrl("");
    setCode("");
    setFilename("");
    setLanguage("");
  }

  const comparison = result?.comparison;
  const source = result?.source;

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
        {!result && !loading && (
          <div className="mx-auto max-w-3xl">
            <div className="mb-6 text-center">
              <h2 className="text-2xl font-bold text-foreground sm:text-3xl">
                Analisi automatica della sicurezza del codice
              </h2>
              <p className="mt-2 text-muted-foreground">
                Fornisci un file di codice (URL Raw/Gist) oppure incolla il sorgente.
                Tre modelli AI lo analizzano in parallelo e confrontano le vulnerabilità trovate.
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
                  Avvia analisi
                </Button>
              </div>
            </form>

            <div className="mt-4 flex items-center justify-center gap-2 text-xs text-muted-foreground/70">
              <Github className="h-3.5 w-3.5" />
              <span>Analisi eseguita lato backend con Apache OpenWhisk / Nuvolaris</span>
            </div>
          </div>
        )}

        {loading && (
          <div className="mx-auto flex max-w-3xl flex-col items-center justify-center py-24 text-center">
            <Loader2 className="h-10 w-10 animate-spin text-primary" />
            <h2 className="mt-4 text-lg font-semibold text-foreground">Analisi in corso...</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Tre modelli stanno analizzando il codice in parallelo. Può richiedere qualche minuto.
            </p>
          </div>
        )}

        {result && !loading && comparison && (
          <div className="space-y-8">
            {/* Top bar: source + overall risk + reset */}
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <FileCode className="h-5 w-5" />
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Risultato analisi</p>
                  <p className="font-semibold text-foreground">
                    {source?.language || "Codice"} · {source?.lines ?? 0} righe · {(source?.size ?? 0)} byte
                    {source?.type === "url" && source.url ? ` · da URL` : " · da input"}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <p className="text-xs text-muted-foreground">Rischio complessivo</p>
                  <RiskBadge risk={comparison.overall_risk} />
                </div>
                <Button variant="outline" onClick={reset} className="gap-2">
                  Nuova analisi
                </Button>
              </div>
            </div>

            {/* Comparison summary */}
            <section className="rounded-xl border border-border bg-card p-6 shadow-sm">
              <div className="flex items-center gap-2">
                <Gauge className="h-5 w-5 text-primary" />
                <h3 className="text-lg font-semibold text-foreground">Confronto e riepilogo</h3>
              </div>
              <p className="mt-3 text-sm text-muted-foreground">{comparison.summary}</p>

              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-border bg-muted/40 p-4 text-center">
                  <p className="text-2xl font-bold text-foreground">{comparison.common.length}</p>
                  <p className="text-xs text-muted-foreground">Vulnerabilità comuni (concordanti)</p>
                </div>
                <div className="rounded-lg border border-border bg-muted/40 p-4 text-center">
                  <p className="text-2xl font-bold text-foreground">{comparison.unique.length}</p>
                  <p className="text-xs text-muted-foreground">Segnalate da un solo modello</p>
                </div>
                <div className="rounded-lg border border-border bg-muted/40 p-4 text-center">
                  <p className="text-2xl font-bold text-foreground">
                    {comparison.models_ok.length}/{result.models?.length ?? 3}
                  </p>
                  <p className="text-xs text-muted-foreground">Modelli attivi</p>
                </div>
              </div>

              {comparison.models_failed && comparison.models_failed.length > 0 && (
                <div className="mt-4 flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>
                    Modelli non disponibili: {comparison.models_failed.join(", ")}. Verifica che i modelli siano
                    disponibili in Ollama, che <code className="font-mono">OLLAMA_HOST</code> sia un URL valido
                    (es. <code className="font-mono">https://ollama.com</code>) e, per Ollama Cloud,
                    che <code className="font-mono">OLLAMA_API_KEY</code> sia impostato.
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
                    Vulnerabilità comuni ({comparison.common.length})
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

            {/* Per-model reports */}
            <section>
              <div className="mb-3 flex items-center gap-2">
                <Cpu className="h-5 w-5 text-primary" />
                <h3 className="text-lg font-semibold text-foreground">Report per modello</h3>
              </div>
              <div className="grid gap-4 lg:grid-cols-3">
                {result.models?.map((m) => (
                  <ModelReportCard key={m.id} result={m} />
                ))}
              </div>
            </section>
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