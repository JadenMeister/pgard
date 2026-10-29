import type { Coverage, Finding, ScanResult } from "./contract.js";
import { createFindingFingerprint } from "./fingerprint.js";
import { redactEvidence } from "./redact.js";
import {
  SKIPPED_DIRECTORIES,
  isFileInWalkedSkipDirectory,
  isUnderJvmSourceRoot,
} from "./skipped-directories.js";

/**
 * Scan comparison: which findings are new, no longer reported, unchanged or moved between two
 * results of the same repository. Pure and synchronous; the caller loads both results (through
 * `readScanResult` or the result store) and decides what "previous" is.
 *
 * Why this lives in `@pgard/findings`: it only needs the result contract, the fingerprint helper
 * and the redactor, all of which are here. `@pgard/result-store` stays an I/O package (files,
 * permissions, retention) and the web client may import this module (no Node APIs).
 *
 * ## Principle
 *
 * "No longer reported" needs positive evidence that the place was analyzed this time. A new
 * finding is never hidden: it is always listed, with a flag when the baseline was incomplete.
 * "No longer reported" is not "fixed": the code may also have been skipped, renamed or
 * reclassified, which no result can prove otherwise.
 *
 * ## Design note: line-insensitive finding identity
 *
 * `Finding.id` hashes the line number, so code that only moved reads as "gone + new". The
 * comparison therefore uses its own identity, computed at compare time from fields that are
 * already in the result (no schema change): `findingIdentity()`. It is only computed from stored,
 * redacted fields (the evidence is run through `redactEvidence` again); no source text is read.
 *
 * - Source (file location, scope `code`): rule id + repository-relative path + normalized
 *   evidence. The evidence is the redacted description of the flow (for example
 *   `req.query -> concat -> query()`), i.e. the code shape, not code text. Normalization
 *   collapses whitespace and drops `line N` / `file.ext:N` references. The enclosing function
 *   name is not stored in results, so it is not part of the identity; duplicates in one file
 *   that share rule + shape are told apart by pairing (below). Trade-off: if one of two
 *   same-shape findings in a file is removed and an unrelated one of the same shape is added far
 *   away, the pair reads as "moved". Same shape in the same file is the same finding to this
 *   tool.
 * - History (location kind `commit`, or scope `history`): rule id + path + commit + the
 *   normalized evidence, which names the secret kind and where it was found. The secret value
 *   itself is never stored, so no value hash exists. `PG-HYGIENE-001` evidence carries the HEAD
 *   revision and file counts, which change with every commit, so only its rule and path count.
 * - Web (location kind `url`): rule id + origin + path (query and fragment dropped) + the
 *   evidence with version-like quoted values removed. That keeps header and cookie names but not
 *   the version, so a version bump is not "gone + new".
 *
 * ## Collisions
 *
 * Findings that share an identity inside one scan form a group. Previous and current groups with
 * the same identity are paired one-to-one, nearest line first (greedy on the absolute line
 * difference; ties break by group order, i.e. the lower line, so the result is deterministic).
 * Leftovers are `noLongerReported` (previous side) or `new` (current side). A missing line is far
 * from any real line.
 *
 * ## Moved versus changed
 *
 * - `unchanged`: paired and on the same line.
 * - `moved`: paired, but the line differs. `delta` is `current - previous`.
 * - `changed` is not a bucket: a pair whose severity, status or confidence differ carries
 *   `changed`. A finding whose rule, path, shape, commit or URL changed has a different identity.
 *
 * ## Comparability
 *
 * An area is `comparable` only when it is `completed` in both scans (web areas also need the same
 * `target.webOrigin`). A finding is blocked from "no longer reported" by:
 * - the areas whose `ruleIds` list its rule in either scan (if none does, every area of its scope
 *   that ran), and
 * - skip signals in its scope: an area with no `ruleIds` that is `partial` (files over the size
 *   limit, unsupported ORMs, manifests), or that is `completed` but present in only one scan or
 *   with a different note (skipped dependency directories, symbolic links, and files left out by
 *   `pgard.config.json`: `source:config-excluded` carries a hash of the patterns and of the excluded
 *   file set, so a newly excluded file is never "no longer reported"). A `not_tested`
 *   area with no rules (a language PGARD detects but cannot analyze yet) blocks nothing.
 * It is also blocked when `tool.version` differs, since rules may have changed.
 * A pair found in both scans is always reported as unchanged or moved. Unpaired current findings
 * are always `new`, including those from an area that did not run last time (a scope change); those
 * with a blocking reason are also in `newInUncertainAreas`, and `uncertainAreas` names the areas.
 */

export type NotComparableReason =
  "partial" | "not_tested" | "only_in_previous" | "only_in_current" | "not_run" | "other_origin";

export interface AreaComparability {
  area: string;
  scope: Coverage["scope"];
  comparable: boolean;
  /** Set when `comparable` is false. */
  reason: NotComparableReason | null;
  /** True when the area lists rules in either scan. */
  ownsRules: boolean;
  /** Findings that could not be compared because of this area. */
  held: number;
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
  /** Every unpaired finding of the current scan. Never hidden. */
  new: Finding[];
  /** The subset of `new` whose baseline was incomplete (it may have existed before). */
  newInUncertainAreas: Finding[];
  /** In the previous scan only, and the place was fully analyzed both times. */
  noLongerReported: Finding[];
  unchanged: ComparedPair[];
  moved: ComparedPair[];
  /** Unpaired previous findings that could not be checked; never counted as gone. */
  notComparable: Finding[];
  /** Areas that made some `new` finding uncertain, most findings first. */
  uncertainAreas: string[];
  /** True when `tool.version` differs between the scans. */
  toolVersionChanged: boolean;
  /** Every area seen in either scan. */
  areas: AreaComparability[];
}

const WHITESPACE = /\s+/g;
// `line 12`, `lines 3-9`, `ln 4`, and `:12` / `:12:3` only right after a file extension.
const LINE_REFERENCE =
  /\b(?:lines?|ln)\s*\d+(?:\s*-\s*\d+)?|(?<=\.[A-Za-z0-9]{1,6}):\d+(?::\d+)?\b/gi;
const QUOTED_VERSION = /"[^"]*\d+\.\d+[^"]*"|'[^']*\d+\.\d+[^']*'/g;
const HYGIENE_RULE = "PG-HYGIENE-001";

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

function normalizeEvidence(finding: Finding, family: Family): string {
  if (finding.ruleId === HYGIENE_RULE) return "";
  // A dependency finding is the same issue as long as package, version and advisory are the same;
  // its evidence (range, fixed versions, severity) follows the advisory data and may change.
  if (finding.dependency !== undefined) {
    const { ecosystem, name, version, advisoryId } = finding.dependency;
    return `${ecosystem}:${name}@${version}:${advisoryId}`;
  }
  // Redact again: the stored text should already be clean, but identity must never depend on
  // (or hash) anything a redactor would have removed.
  let text = redactEvidence(finding.evidence);
  if (family === "web") text = text.replace(QUOTED_VERSION, '""');
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
    cause: `${family}:${normalizeEvidence(finding, family)}`,
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

/**
 * Skip areas whose own status (partial or informational) never makes the whole area "not
 * comparable"; what they block is decided per finding in isSkipSignal.
 */
const NOTE_ONLY_AREAS: ReadonlySet<string> = new Set([
  "source:minified",
  "source:build-output",
  "source:xml-skipped",
  "source:unreadable-files",
  "source:special-files",
  "deps:unsupported",
]);
const BUILD_OUTPUT_AREA = "source:build-output";
const XML_AREA = "source:xml-skipped";
const SPECIAL_AREA = "source:special-files";

/** The path has a directory segment that the source walk skips by name (`dist`, `build`, ...). */
function isUnderSkippedDirectory(findingPath: string | null | undefined): boolean {
  return (
    typeof findingPath === "string" &&
    !isUnderJvmSourceRoot(findingPath) &&
    !isFileInWalkedSkipDirectory(findingPath) &&
    findingPath.split("/").some((s) => SKIPPED_DIRECTORIES.has(s))
  );
}

/**
 * The path is below a skip-named directory that the walk entered in both scans (they recorded it
 * as containing source), so the finding is ordinary. A scan that has the area but not the list (a
 * result older than 1.3) or a list that may be incomplete gives no such guarantee.
 */
function isUnderWalkedInBoth(
  findingPath: string | null | undefined,
  a: Coverage | undefined,
  b: Coverage | undefined,
): boolean {
  if (typeof findingPath !== "string" || a === undefined || b === undefined) return false;
  const lists = [a.walkedDirectories, b.walkedDirectories];
  if (lists.some((list) => list === undefined || !list.complete)) return false;
  return lists.every((list) =>
    (list as { paths: string[] }).paths.some(
      (prefix) => findingPath === prefix || findingPath.startsWith(`${prefix}/`),
    ),
  );
}

/** An `.xml` file under a `res` or `target` segment, which the walk does not check for mappers. */
function isSkippedResourceXml(findingPath: string | null | undefined): boolean {
  return (
    typeof findingPath === "string" &&
    findingPath.toLowerCase().endsWith(".xml") &&
    findingPath.split("/").some((s) => s === "res" || s === "target")
  );
}

function compareAreas(
  previous: readonly Coverage[],
  current: readonly Coverage[],
  isOriginChanged: boolean,
): Map<string, AreaComparability> {
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
    // A scope change comes first: an area that did not run last time has no baseline at all, which
    // is a different statement from "partially scanned".
    if (ran(a) && !ran(b)) reason = "only_in_previous";
    else if (!ran(a) && ran(b)) reason = "only_in_current";
    else if (!ran(a) && !ran(b)) reason = "not_run";
    // Skipped minified bundles stay partial overall, but only a change in the skipped set (the
    // note) makes the comparison unreliable; see isSkipSignal.
    else if (!NOTE_ONLY_AREAS.has(area) && (a?.status === "partial" || b?.status === "partial"))
      reason = "partial";
    else if (a?.status === "not_tested" || b?.status === "not_tested") reason = "not_tested";
    else if (isOriginChanged && scope === "web") reason = "other_origin";
    result.set(area, {
      area,
      scope,
      comparable: reason === null,
      reason,
      ownsRules: (a?.ruleIds.length ?? 0) > 0 || (b?.ruleIds.length ?? 0) > 0,
      held: 0,
    });
  }
  return result;
}

interface Context {
  before: Map<string, Coverage>;
  after: Map<string, Coverage>;
  coverage: Coverage[];
  areas: Map<string, AreaComparability>;
}

/** A rule-less area that shows files or directories were skipped in this scope. */
function isSkipSignal(area: string, ctx: Context, finding: Finding): boolean {
  const a = ctx.before.get(area);
  const b = ctx.after.get(area);
  const entries = [a, b].filter((entry): entry is Coverage => entry !== undefined);
  if (entries.some((entry) => entry.ruleIds.length > 0)) return false;
  if (area === SPECIAL_AREA) return false;
  if (area === XML_AREA) return isSkippedResourceXml(finding.location.path);
  // Informational build-output notes only matter for findings in such a directory; the partial
  // form (no source found elsewhere) is a whole-scope signal that follows its note.
  if (area === BUILD_OUTPUT_AREA && !entries.some((entry) => entry.status === "partial")) {
    // Same skip set in both scans: such a finding could not have been analyzed in only one.
    return (
      a?.note !== b?.note &&
      isUnderSkippedDirectory(finding.location.path) &&
      !isUnderWalkedInBoth(finding.location.path, a, b)
    );
  }
  if (NOTE_ONLY_AREAS.has(area)) return a?.note !== b?.note;
  if (entries.some((entry) => entry.status === "partial")) return true;
  const ran = (entry: Coverage | undefined) => entry?.status === "completed";
  if (ran(a) !== ran(b)) return true;
  return a !== undefined && b !== undefined && ran(a) && a.note !== b.note;
}

/** Area ids that stop `finding` from being compared; null when no area covers it at all. */
function blockingAreas(finding: Finding, ctx: Context): string[] | null {
  const scopes = new Set<string>(finding.sources);
  const listed = new Set(
    ctx.coverage.filter((entry) => entry.ruleIds.includes(finding.ruleId)).map((e) => e.area),
  );
  let owners = listed;
  if (owners.size === 0) {
    owners = new Set(
      ctx.coverage
        .filter(
          (entry) =>
            scopes.has(entry.scope) && (entry.status === "completed" || entry.status === "partial"),
        )
        .map((entry) => entry.area),
    );
  }
  if (owners.size === 0) return null;
  const blocking = new Set([...owners].filter((area) => ctx.areas.get(area)?.comparable !== true));
  for (const [area, info] of ctx.areas) {
    if (scopes.has(info.scope) && !owners.has(area) && isSkipSignal(area, ctx, finding)) {
      blocking.add(area);
    }
  }
  return [...blocking];
}

export function compareScans(previous: ScanResult, current: ScanResult): ScanComparison {
  const isOriginChanged = previous.target.webOrigin !== current.target.webOrigin;
  const areas = compareAreas(previous.coverage, current.coverage, isOriginChanged);
  const ctx: Context = {
    before: new Map(previous.coverage.map((entry) => [entry.area, entry])),
    after: new Map(current.coverage.map((entry) => [entry.area, entry])),
    coverage: [...previous.coverage, ...current.coverage],
    areas,
  };
  const toolVersionChanged = previous.tool.version !== current.tool.version;

  const comparison: ScanComparison = {
    new: [],
    newInUncertainAreas: [],
    noLongerReported: [],
    unchanged: [],
    moved: [],
    notComparable: [],
    toolVersionChanged,
    uncertainAreas: [],
    areas: [],
  };
  const uncertainCounts = new Map<string, number>();
  const hold = (blocking: string[]) => {
    for (const area of blocking) {
      const info = areas.get(area);
      if (info) info.held += 1;
    }
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
      const blocking = blockingAreas(finding, ctx);
      if (blocking === null || blocking.length > 0 || toolVersionChanged) {
        comparison.notComparable.push(finding);
        hold(blocking ?? []);
      } else {
        comparison.noLongerReported.push(finding);
      }
    });
    newGroup.forEach((finding, index) => {
      if (pairedNew.has(index)) return;
      comparison.new.push(finding);
      const blocking = blockingAreas(finding, ctx);
      if (blocking === null || blocking.length > 0) {
        comparison.newInUncertainAreas.push(finding);
        hold(blocking ?? []);
        for (const area of blocking ?? []) {
          uncertainCounts.set(area, (uncertainCounts.get(area) ?? 0) + 1);
        }
      }
    });
  }
  comparison.uncertainAreas = [...uncertainCounts.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .map(([area]) => area);
  comparison.areas = [...areas.values()];
  return comparison;
}

/**
 * Areas worth telling the user about: any area holding findings back (this includes skip signals,
 * which are "completed" but changed), and rule-owning areas that were not comparable. Those holding back the most findings come first, so
 * rule-less language-track entries ("detected, no rules yet") never crowd them out.
 */
export function notComparableAreas(comparison: ScanComparison): AreaComparability[] {
  return comparison.areas
    .filter(
      (area) => area.held > 0 || (!area.comparable && area.reason !== "not_run" && area.ownsRules),
    )
    .sort(
      (a, b) =>
        b.held - a.held || Number(b.ownsRules) - Number(a.ownsRules) || (a.area < b.area ? -1 : 1),
    );
}
