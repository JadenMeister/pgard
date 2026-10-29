import type { Severity } from "@pgard/findings";
import type { ReducedAdvisory } from "../osv/reduce.js";

export type SeveritySource = "cvss" | "database" | "unknown";

export interface AdvisorySeverity {
  /** `null` when neither a CVSS score nor a database label exists. */
  level: Severity | null;
  source: SeveritySource;
  /** CVSS base score (0-10) when it was computed from a v3 vector. */
  score?: number;
  /** The CVSS vector as published, when there is one (also for versions not scored here). */
  vector?: string;
}

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

function roundUp(value: number): number {
  const integer = Math.round(value * 100000);
  return integer % 10000 === 0 ? integer / 100000 : (Math.floor(integer / 10000) + 1) / 10;
}

/** CVSS v3.0 / v3.1 base score from a vector, or `null` if the vector is not a valid v3 vector. */
export function cvss3BaseScore(vector: string): number | null {
  const match = /^CVSS:3\.[01]\/(.+)$/.exec(vector);
  if (match === null) return null;
  const metrics = new Map<string, string>();
  for (const part of (match[1] as string).split("/")) {
    const [key, value, ...rest] = part.split(":");
    if (key === undefined || value === undefined || rest.length > 0) return null;
    if (metrics.has(key)) return null;
    metrics.set(key, value);
  }
  const get = (key: string): string | undefined => metrics.get(key);
  const av = WEIGHTS.AV[get("AV") as keyof typeof WEIGHTS.AV];
  const ac = WEIGHTS.AC[get("AC") as keyof typeof WEIGHTS.AC];
  const ui = WEIGHTS.UI[get("UI") as keyof typeof WEIGHTS.UI];
  const c = WEIGHTS.CIA[get("C") as keyof typeof WEIGHTS.CIA];
  const i = WEIGHTS.CIA[get("I") as keyof typeof WEIGHTS.CIA];
  const a = WEIGHTS.CIA[get("A") as keyof typeof WEIGHTS.CIA];
  const scope = get("S");
  const privilege = get("PR");
  if ([av, ac, ui, c, i, a].some((value) => value === undefined)) return null;
  if (scope !== "U" && scope !== "C") return null;
  if (privilege !== "N" && privilege !== "L" && privilege !== "H") return null;
  const pr =
    privilege === "N"
      ? 0.85
      : privilege === "L"
        ? scope === "U"
          ? 0.62
          : 0.68
        : scope === "U"
          ? 0.27
          : 0.5;
  const iss = 1 - (1 - (c as number)) * (1 - (i as number)) * (1 - (a as number));
  const impact = scope === "U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * (av as number) * (ac as number) * pr * (ui as number);
  const raw =
    scope === "U"
      ? Math.min(impact + exploitability, 10)
      : Math.min(1.08 * (impact + exploitability), 10);
  return roundUp(raw);
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

const LABELS: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low",
};

/**
 * Severity of an advisory: the CVSS v3 base score computed from its vector when there is one;
 * otherwise the database's own label (`database_specific.severity`, as GitHub advisories carry);
 * otherwise unknown. CVSS v4 vectors are kept but not scored (PGARD does not implement v4's
 * lookup-table scoring), so such an advisory falls back to its label.
 */
export function advisorySeverity(advisory: ReducedAdvisory): AdvisorySeverity {
  let vector: string | undefined;
  for (const item of advisory.severity ?? []) {
    vector ??= item.score;
    if (item.type !== "CVSS_V3") continue;
    const score = cvss3BaseScore(item.score);
    if (score !== null) {
      return { level: severityFromScore(score), source: "cvss", score, vector: item.score };
    }
  }
  const label = advisory.label === undefined ? undefined : LABELS[advisory.label.toUpperCase()];
  if (label !== undefined) {
    return { level: label, source: "database", ...(vector === undefined ? {} : { vector }) };
  }
  return { level: null, source: "unknown", ...(vector === undefined ? {} : { vector }) };
}

const ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

/** The most severe of several advisories that describe the same issue. */
export function strongestSeverity(items: readonly AdvisorySeverity[]): AdvisorySeverity {
  let best: AdvisorySeverity = { level: null, source: "unknown" };
  for (const item of items) {
    if (item.level === null) continue;
    if (best.level === null || ORDER.indexOf(item.level) > ORDER.indexOf(best.level)) best = item;
  }
  return best.level === null ? (items.find((item) => item.vector !== undefined) ?? best) : best;
}
