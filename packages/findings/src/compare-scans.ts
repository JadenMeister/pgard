import type { Coverage, Finding, ScanResult } from "./contract.js";
import { createFindingFingerprint } from "./fingerprint.js";
import { redactEvidence } from "./redact.js";

/**
 * Scan comparison: which findings are new, fixed, unchanged or moved between two results of the
 * same repository. Pure and synchronous; the caller loads both results (through `readScanResult`
 * or the result store) and decides what "previous" is.
 *
 * Why this lives in `@pgard/findings`: it only needs the result contract, the fingerprint helper
 * and the redactor, all of which are here. `@pgard/result-store` stays an I/O package (files,
 * permissions, retention) and the web client may import this module (no Node APIs).
 *
 * ## Design note: line-insensitive finding identity
 *
 * `Finding.id` hashes the line number, so code that only moved reads as "fixed + new". The
 * comparison therefore uses its own identity, computed at compare time from fields that are
 * already in the result (no schema change): `findingIdentity()`. It never leaves this module's
 * output as anything but an opaque hash, and it is only computed from stored, redacted fields
 * (the evidence is run through `redactEvidence` again); no source text is ever read.
 *
 * - Source (file location, scope `code`): rule id + repository-relative path + normalized
 *   evidence. The evidence is the redacted description of the flow (for example
 *   `req.query -> concat -> query()`), i.e. the code shape, not code text. Normalization
 *   collapses whitespace and drops `line N` / `:N` references. The enclosing function name is
 *   not stored in results, so it is not part of the identity; duplicates in one file that share
 *   rule + shape are told apart by pairing (below).
 * - History (location kind `commit`, or scope `history`): rule id + path + commit + the
 *   normalized evidence, which names the secret kind and where it was found. The secret value
 *   itself is never stored, so no value hash exists (and none could be derived).
 * - Web (location kind `url`): rule id + origin + path (query and fragment dropped) + the
 *   evidence with every quoted value removed, which keeps the header name ("Server header
 *   discloses a version") but not the version, so a version bump is not "fixed + new".
 *
 * ## Collisions
 *
 * Findings that share an identity inside one scan form a group. Previous and current groups with
 * the same identity are paired one-to-one, nearest line first (greedy on the absolute line
 * difference; ties break by order, so the result is deterministic). Leftovers are `fixed`
 * (previous side) or `new` (current side). A missing line counts as far from any real line.
 *
 * ## Moved versus changed
 *
 * - `unchanged`: paired and on the same line.
 * - `moved`: paired, but the line differs (code shifted, lines inserted above, file edited
 *   elsewhere). `delta` is `current - previous`.
 * - `changed` is not a bucket: a pair whose severity, status or confidence differ carries
 *   `changed` (the names of the fields). A finding whose rule, path, shape, commit or URL
 *   changed has a different identity and is reported as fixed + new, which is what it is.
 *
 * ## Comparability
 *
 * Each coverage area is `comparable` only when it is `completed` in both scans. An area that
 * ran in one scan only, or was `partial` or `not_tested` in either, is not comparable. A finding
 * belongs to the areas whose `ruleIds` list its rule (in either scan); if no area lists the
 * rule, to every area of its scope. Unpaired findings in an area that is not comparable are
 * neither `new` nor `fixed`: they are returned in `notComparable`, because not seeing a finding
 * in an incomplete scan says nothing about whether it was fixed (and a new finding against an
 * incomplete baseline is not known to be new). A pair found in both scans is always reported as
 * unchanged or moved, since both scans saw it.
 */

export type NotComparableReason =
  "partial" | "not_tested" | "only_in_previous" | "only_in_current" | "not_run";

export interface AreaComparability {
  area: string;
  scope: Coverage["scope"];
  comparable: boolean;
  /** Set when `comparable` is false. */
  reason: NotComparableReason | null;
}

export interface ComparedPair {
  previous: Finding;
  current: Finding;
  /** `current.line - previous.line`; null when either has no line. */
  delta: number | null;
  /** Names of `severity` / `status` / `confidence` that differ; empty when none. */
  changed: ("severity" | "status" | "confidence")[];
}

export interface ScanComparison {
  /** In the current scan only, in a comparable area. */
  new: Finding[];
  /** In the previous scan only, in a comparable area. */
  fixed: Finding[];
  unchanged: ComparedPair[];
  moved: ComparedPair[];
  /** Unpaired findings whose area could not be compared; never counted as new or fixed. */
  notComparable: { previous: Finding[]; current: Finding[] };
  /** Every area seen in either scan. */
  areas: AreaComparability[];
}

const WHITESPACE = /\s+/g;
const LINE_REFERENCE = /\b(?:lines?|ln)\s*\d+(?:\s*-\s*\d+)?|:\d+(?::\d+)?\b/gi;
const QUOTED = /"[^"]*"|'[^']*'|`[^`]*`/g;

type Family = "source" | "history" | "web";

function familyOf(finding: Finding): Family {
  if (finding.location.kind === "url") return "web";
  if (
    finding.location.kind === "commit" ||
    (finding.sources.includes("history") && !finding.sources.includes("code"))
  ) {
    return "history";
  }
  return "source";
}

function webUrl(raw: string | null): string {
  if (raw === null) return "";
  try {
    const parsed = new URL(raw);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return raw.replace(/[?#].*$/s, "");
  }
}

function normalizeEvidence(evidence: string, family: Family): string {
  // Redact again: the stored text should already be clean, but identity must never depend on
  // (or hash) anything a redactor would have removed.
  let text = redactEvidence(evidence);
  if (family === "web") text = text.replace(QUOTED, '""');
  return text.replace(LINE_REFERENCE, "").replace(WHITESPACE, " ").trim();
}

/**
 * Line-insensitive identity of a finding (opaque 128-bit hex). Equal identities mean "the same
 * issue, possibly on another line". Deterministic across runs and machines.
 */
export function findingIdentity(finding: Finding): string {
  const family = familyOf(finding);
  const { location } = finding;
  return createFindingFingerprint({
    ruleId: finding.ruleId,
    location: {
      kind: location.kind,
      path: location.path,
      line: null,
      url: family === "web" ? webUrl(location.url) : location.url,
      commit: location.commit,
    },
    cause: `${family}:${normalizeEvidence(finding.evidence, family)}`,
  });
}

/** Above this many candidate pairs in one group, pairing falls back to line order. */
const MAX_PAIR_CANDIDATES = 40_000;
const NO_LINE_DISTANCE = Number.MAX_SAFE_INTEGER;

function distance(a: Finding, b: Finding): number {
  const lineA = a.location.line;
  const lineB = b.location.line;
  if (lineA === null && lineB === null) return 0;
  if (lineA === null || lineB === null) return NO_LINE_DISTANCE;
  return Math.abs(lineA - lineB);
}

function byLine(a: Finding, b: Finding): number {
  return (
    (a.location.line ?? Number.MAX_SAFE_INTEGER) - (b.location.line ?? Number.MAX_SAFE_INTEGER)
  );
}

/** One-to-one pairing, nearest line first. Returns index pairs into `previous` / `current`. */
function pairGroup(previous: Finding[], current: Finding[]): [number, number][] {
  const pairs: [number, number][] = [];
  if (previous.length * current.length > MAX_PAIR_CANDIDATES) {
    const count = Math.min(previous.length, current.length);
    for (let index = 0; index < count; index += 1) pairs.push([index, index]);
    return pairs;
  }
  const candidates: { p: number; c: number; d: number }[] = [];
  previous.forEach((p, pIndex) =>
    current.forEach((c, cIndex) => candidates.push({ p: pIndex, c: cIndex, d: distance(p, c) })),
  );
  candidates.sort((a, b) => a.d - b.d || a.p - b.p || a.c - b.c);
  const usedPrevious = new Set<number>();
  const usedCurrent = new Set<number>();
  for (const { p, c } of candidates) {
    if (usedPrevious.has(p) || usedCurrent.has(c)) continue;
    usedPrevious.add(p);
    usedCurrent.add(c);
    pairs.push([p, c]);
  }
  return pairs;
}

function groupByIdentity(findings: readonly Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = findingIdentity(finding);
    const group = groups.get(key);
    if (group) group.push(finding);
    else groups.set(key, [finding]);
  }
  for (const group of groups.values()) group.sort(byLine);
  return groups;
}

function compareAreas(previous: readonly Coverage[], current: readonly Coverage[]) {
  const before = new Map(previous.map((entry) => [entry.area, entry]));
  const after = new Map(current.map((entry) => [entry.area, entry]));
  const result = new Map<string, AreaComparability>();
  for (const area of new Set([...before.keys(), ...after.keys()])) {
    const a = before.get(area);
    const b = after.get(area);
    const scope = (b ?? a)?.scope ?? "code";
    const ran = (entry: Coverage | undefined) =>
      entry !== undefined && entry.status !== "not_selected";
    let reason: NotComparableReason | null = null;
    if (a?.status === "partial" || b?.status === "partial") reason = "partial";
    else if (a?.status === "not_tested" || b?.status === "not_tested") reason = "not_tested";
    else if (ran(a) && !ran(b)) reason = "only_in_previous";
    else if (!ran(a) && ran(b)) reason = "only_in_current";
    else if (!ran(a) && !ran(b)) reason = "not_run";
    result.set(area, { area, scope, comparable: reason === null, reason });
  }
  return result;
}

function isComparable(
  finding: Finding,
  coverage: readonly Coverage[],
  areas: Map<string, AreaComparability>,
): boolean {
  let owners = coverage.filter((entry) => entry.ruleIds.includes(finding.ruleId));
  if (owners.length === 0) {
    owners = coverage.filter((entry) => finding.sources.includes(entry.scope));
  }
  const ids = new Set(owners.map((entry) => entry.area));
  if (ids.size === 0) return false;
  return [...ids].every((id) => areas.get(id)?.comparable === true);
}

export function compareScans(previous: ScanResult, current: ScanResult): ScanComparison {
  const areas = compareAreas(previous.coverage, current.coverage);
  const allCoverage = [...previous.coverage, ...current.coverage];
  const comparable = (finding: Finding) => isComparable(finding, allCoverage, areas);

  const comparison: ScanComparison = {
    new: [],
    fixed: [],
    unchanged: [],
    moved: [],
    notComparable: { previous: [], current: [] },
    areas: [...areas.values()],
  };
  const before = groupByIdentity(previous.findings);
  const after = groupByIdentity(current.findings);
  for (const identity of new Set([...before.keys(), ...after.keys()])) {
    const oldGroup = before.get(identity) ?? [];
    const newGroup = after.get(identity) ?? [];
    const pairs = pairGroup(oldGroup, newGroup);
    const pairedOld = new Set(pairs.map(([p]) => p));
    const pairedNew = new Set(pairs.map(([, c]) => c));
    for (const [p, c] of pairs) {
      const was = oldGroup[p] as Finding;
      const now = newGroup[c] as Finding;
      const wasLine = was.location.line;
      const nowLine = now.location.line;
      const pair: ComparedPair = {
        previous: was,
        current: now,
        delta: wasLine === null || nowLine === null ? null : nowLine - wasLine,
        changed: (["severity", "status", "confidence"] as const).filter(
          (field) => was[field] !== now[field],
        ),
      };
      (wasLine === nowLine ? comparison.unchanged : comparison.moved).push(pair);
    }
    oldGroup.forEach((finding, index) => {
      if (pairedOld.has(index)) return;
      (comparable(finding) ? comparison.fixed : comparison.notComparable.previous).push(finding);
    });
    newGroup.forEach((finding, index) => {
      if (pairedNew.has(index)) return;
      (comparable(finding) ? comparison.new : comparison.notComparable.current).push(finding);
    });
  }
  return comparison;
}

/** Areas that make a comparison incomplete and that one of the two scans actually requested. */
export function notComparableAreas(comparison: ScanComparison): AreaComparability[] {
  return comparison.areas.filter((area) => !area.comparable && area.reason !== "not_run");
}
