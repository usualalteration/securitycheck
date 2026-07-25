// Client-side aggregation of per-model results into the comparison view.
// Mirrors the server-side logic that used to live in v1/analyze, but now runs
// in the browser because models are analyzed one at a time via v1/analyze-model.

import type { Finding, GroupedFinding, ModelResult, Severity } from "./security";

export const SEVERITY_SCORE: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
};

export const SEVERITY_LABEL_IT: Record<Severity, string> = {
  critical: "Critico",
  high: "Alto",
  medium: "Medio",
  low: "Basso",
  info: "Info",
  none: "Nessuno",
};

export function severityLabel(sev: string): string {
  return SEVERITY_LABEL_IT[(sev || "info").toLowerCase() as Severity] ?? sev;
}

function normTitle(title: string): string {
  const t = (title || "").toLowerCase();
  return t.replace(/[^a-z0-9]+/g, " ").trim();
}

function sevScore(sev: string): number {
  return SEVERITY_SCORE[(sev || "info").toLowerCase() as Severity] ?? 1;
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

export function buildComparison(modelResults: ModelResult[]): Comparison {
  const groups: Record<
    string,
    {
      title: string;
      models: string[];
      maxSeverity: Severity;
      maxScore: number;
      categories: Set<string>;
      descriptions: { model: string; text: string }[];
      recommendations: { model: string; text: string }[];
    }
  > = {};

  for (const m of modelResults) {
    if (!m.ok) continue;
    for (const f of m.findings || []) {
      const key = normTitle(f.title) || (f.title || "").toLowerCase();
      if (!key) continue;
      let g = groups[key];
      if (!g) {
        g = {
          title: f.title,
          models: [],
          maxSeverity: "info",
          maxScore: 0,
          categories: new Set(),
          descriptions: [],
          recommendations: [],
        };
        groups[key] = g;
      }
      if (!g.models.includes(m.name)) g.models.push(m.name);
      if (sevScore(f.severity) > g.maxScore) {
        g.maxScore = sevScore(f.severity);
        g.maxSeverity = f.severity;
      }
      if (f.category) g.categories.add(f.category);
      if (f.description) g.descriptions.push({ model: m.name, text: f.description });
      if (f.recommendation) g.recommendations.push({ model: m.name, text: f.recommendation });
    }
  }

  const common: GroupedFinding[] = [];
  const unique: GroupedFinding[] = [];

  for (const g of Object.values(groups)) {
    const entry: GroupedFinding = {
      title: g.title,
      severity: g.maxSeverity,
      severity_label: severityLabel(g.maxSeverity),
      category: Array.from(g.categories).filter(Boolean).sort().join(", ") || "Generale",
      models: [...g.models],
      agreement: g.models.length,
      description: g.descriptions[0]?.text ?? "",
      descriptions: g.descriptions,
      recommendations: g.recommendations,
    };
    if (g.models.length >= 2) {
      common.push(entry);
    } else {
      entry.model = g.models[0] ?? "";
      unique.push(entry);
    }
  }

  common.sort((a, b) => sevScore(b.severity) - sevScore(a.severity));
  unique.sort((a, b) => sevScore(b.severity) - sevScore(a.severity));

  const commonMax = common.length ? Math.max(...common.map((c) => sevScore(c.severity))) : 0;
  const uniqueMax = unique.length ? Math.max(...unique.map((u) => sevScore(u.severity))) : 0;

  let effective = Math.max(commonMax, uniqueMax >= 4 ? uniqueMax : 0);
  if (commonMax === 0 && uniqueMax >= 4) effective = 4;
  else if (commonMax === 0 && uniqueMax === 3) effective = 3;
  else if (effective === 0) effective = uniqueMax;

  let riskLabel = "Nessuno";
  for (const [sev, score] of Object.entries(SEVERITY_SCORE).sort((a, b) => b[1] - a[1])) {
    if (effective >= score && score > 0) {
      riskLabel = SEVERITY_LABEL_IT[sev as Severity] ?? sev;
      break;
    }
  }

  const totalFindings = modelResults
    .filter((m) => m.ok)
    .reduce((acc, m) => acc + (m.findings?.length ?? 0), 0);
  const modelsOk = modelResults.filter((m) => m.ok).map((m) => m.name);
  const modelsFailed = modelResults.filter((m) => !m.ok).map((m) => m.name);

  const summaryParts: string[] = [];
  summaryParts.push(`Analisi completata con ${modelsOk.length}/${modelResults.length} modelli attivi.`);
  summaryParts.push(`Trovate ${totalFindings} vulnerabilita totali segnalate.`);
  summaryParts.push(`${common.length} vulnerabilita individuate da piu modelli (concordanti).`);
  summaryParts.push(`${unique.length} vulnerabilita segnalate da un solo modello.`);
  if (modelsFailed.length) summaryParts.push(`Modelli non disponibili: ${modelsFailed.join(", ")}.`);
  summaryParts.push(`Livello di rischio complessivo stimato: ${riskLabel}.`);

  return {
    common,
    unique,
    overall_risk: riskLabel,
    overall_score: effective,
    summary: summaryParts.join(" "),
    models_ok: modelsOk,
    models_failed: modelsFailed,
  };
}

export function findingFromModel(f: Finding): Finding {
  return f;
}