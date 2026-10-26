import { createHash } from "node:crypto";
import {
  INCREMENTAL_STATE_FORMAT,
  type CachedSourceFile,
  type Coverage,
  type Finding,
  type IncrementalFullReason,
  type IncrementalState,
  type ScanResult,
  type ScanScope,
} from "@pgard/findings";
import {
  isAncestorCommit,
  listChangedPaths,
  type HistoryIncrementalBase,
} from "@pgard/git-history";
import { GRAMMAR_SHA256 } from "@pgard/source-analysis";
import type { AuthorizationOutcome } from "@pgard/policy";
import type { ProjectConfigLoad } from "./project-config.js";
import { RULE_LOCALITY, unclassifiedRules } from "./rule-locality.js";
import { listSupportedRules } from "./rules.js";
import { ANALYZER_HASH } from "./analyzer-hash.js";
import { PGARD_VERSION } from "./version.js";

/** The stored scan an incremental scan builds on. */
export interface IncrementalBase {
  result: ScanResult;
  /** The per-file data stored with it; null when there is none (older PGARD, too large). */
  state: IncrementalState | null;
  /** Why a state is missing although one was offered for storing (see the result store). */
  stateOmitted?: "too_large" | "rejected" | null;
}

export type IncrementalBaseLoad =
  | { kind: "found"; base: IncrementalBase }
  | {
      kind: "none";
      reason: Extract<
        IncrementalFullReason,
        "no_previous_scan" | "store_unavailable" | "previous_unreadable" | "scopes_changed"
      >;
    };

/** Supplied by the launcher; scan-core never touches the result store itself. */
export interface IncrementalDependencies {
  /** The user asked for a full scan (`--full`). */
  forceFull?: boolean;
  /**
   * Called once, after the gate allowed the scan: the newest stored scan of this repository that
   * covers the same scopes and that is readable and within the retention limit.
   */
  loadBase: (
    outcome: AuthorizationOutcome,
    requestedScopes: readonly ScanScope[],
  ) => Promise<IncrementalBaseLoad>;
  /** Receives what a later scan needs; the launcher stores it next to the result. */
  onState?: (state: IncrementalState, scanId: string) => void;
}

export interface AreaPlan {
  mode: "incremental" | "full";
  reason: IncrementalFullReason | null;
}

export interface IncrementalPlan {
  base: { scanId: string; revision: string | null } | null;
  code: AreaPlan | null;
  history: AreaPlan | null;
  /** Files of the stored scan that may be reused, by path (content is still checked). */
  reuseFiles: Map<string, CachedSourceFile> | null;
  /** Short label of the stored scan for coverage notes. */
  label: string;
  historyBase: HistoryIncrementalBase | null;
}

const INCREMENTAL_AREA: AreaPlan = { mode: "incremental", reason: null };

function full(reason: IncrementalFullReason): AreaPlan {
  return { mode: "full", reason };
}

/** The findings of a rule that decides each finding from one file (see `RULE_LOCALITY`). */
const isFileLocalRule = (ruleId: string): boolean =>
  Object.hasOwn(RULE_LOCALITY, ruleId) && RULE_LOCALITY[ruleId]?.locality === "file-local";

/**
 * A cached entry may only hold findings of file-local rules, located in its own file, once per
 * path. Anything else cannot come from a scan of PGARD, so the whole state is refused.
 */
function entriesAreStructurallySound(entries: readonly CachedSourceFile[]): boolean {
  const paths = new Set<string>();
  for (const entry of entries) {
    if (paths.has(entry.path)) return false;
    paths.add(entry.path);
    for (const finding of entry.findings) {
      if (finding.location.path !== entry.path || !isFileLocalRule(finding.ruleId)) return false;
    }
  }
  return true;
}

/**
 * Severity, status, line, rule, evidence and (unless the result lowered it for test or vendored
 * code) confidence of a cached finding against the stored one. A difference only costs a re-scan.
 */
function sameContent(cached: Finding, stored: Finding): boolean {
  return (
    cached.ruleId === stored.ruleId &&
    cached.severity === stored.severity &&
    cached.status === stored.status &&
    cached.location.line === stored.location.line &&
    cached.evidence === stored.evidence &&
    (stored.context !== undefined || cached.confidence === stored.confidence)
  );
}

/**
 * Entries whose findings are the findings the stored result lists for that file (compared by
 * id among file-local rules). An entry that disagrees (emptied, extended or edited) is dropped,
 * so its file is analyzed again instead of trusting the cache.
 */
function entriesAgreeingWithResult(
  entries: readonly CachedSourceFile[],
  result: ScanResult,
): CachedSourceFile[] {
  const listed = new Map<string, Map<string, Finding[]>>();
  for (const finding of result.findings) {
    const filePath = finding.location.path;
    if (
      filePath === null ||
      !finding.sources.includes("code") ||
      finding.location.commit !== null ||
      !isFileLocalRule(finding.ruleId)
    ) {
      continue;
    }
    let byId = listed.get(filePath);
    if (byId === undefined) listed.set(filePath, (byId = new Map()));
    byId.set(finding.id, [...(byId.get(finding.id) ?? []), finding]);
  }
  return entries.filter((entry) => {
    const expected = listed.get(entry.path) ?? new Map<string, Finding[]>();
    const cached = new Set(entry.findings.map((finding) => finding.id));
    if (expected.size !== cached.size || ![...cached].every((id) => expected.has(id))) return false;
    // Same identity is not enough: what a finding says must be what the stored result says (a
    // finding of one id may stand for several equal ones that were merged).
    return [...expected.values()].every((listedFindings) =>
      listedFindings.every((stored) =>
        entry.findings.some((own) => own.id === stored.id && sameContent(own, stored)),
      ),
    );
  });
}

/** Everything that decides what an analyzer reports for the same file text. */
export function computeAnalysisKey(): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        format: INCREMENTAL_STATE_FORMAT,
        tool: PGARD_VERSION,
        rules: listSupportedRules(),
        grammars: GRAMMAR_SHA256,
        // PGARD ships no vulnerability database; the field is kept so a future one invalidates.
        advisoryDb: { version: null, updatedAt: null },
      }),
    )
    .digest("hex");
}

/** A stable fingerprint of what `pgard.config.json` means to this scan. */
export function fingerprintConfig(load: ProjectConfigLoad): string | null {
  if (load.state === "absent") return null;
  const text =
    load.state === "loaded"
      ? `loaded:${JSON.stringify(load.config)}`
      : `invalid:${load.problems.join("\n")}`;
  return createHash("sha256").update(text).digest("hex");
}

/**
 * Areas of the stored scan that block reuse: one that ran rules (or that is the whole scope, as
 * after an analyzer failure) and did not complete. Areas that only note something found in the
 * walk (an unsupported language, a skipped directory, a configuration note) run no rule, keep no
 * data and are computed again on every scan, so they cannot make reused data stale.
 */
export function blockingCoverage(result: ScanResult): Coverage | null {
  for (const entry of result.coverage) {
    if (entry.scope !== "code" && entry.scope !== "history") continue;
    if (entry.status !== "partial" && entry.status !== "not_tested") continue;
    const isWholeScope = entry.area === "code" || entry.area === "history";
    if (entry.scope === "history" || isWholeScope || entry.ruleIds.length > 0) return entry;
  }
  return null;
}

const COMMIT_RULES = ["PG-SECRET-001", "PG-SECRET-003"];
const TRACKED_RULES = ["PG-SECRET-001", "PG-SECRET-002"];

function historyBaseOf(result: ScanResult, revision: string): HistoryIncrementalBase | null {
  const historyFindings = result.findings.filter((finding) => finding.sources.includes("history"));
  const carried = historyFindings.filter(
    (finding) => COMMIT_RULES.includes(finding.ruleId) && finding.location.commit !== null,
  );
  const trackedFindingPaths = historyFindings
    .filter(
      (finding: Finding) =>
        TRACKED_RULES.includes(finding.ruleId) &&
        finding.location.commit === null &&
        finding.location.path !== null,
    )
    .map((finding) => finding.location.path as string);
  return { baseRevision: revision, carried, trackedFindingPaths };
}

function sameScopes(a: readonly ScanScope[], b: readonly ScanScope[]): boolean {
  return a.length === b.length && a.every((scope, index) => scope === b[index]);
}

function allFull(
  reason: IncrementalFullReason,
  scopes: readonly ScanScope[],
  base: IncrementalPlan["base"] = null,
): IncrementalPlan {
  return {
    base,
    code: scopes.includes("code") ? full(reason) : null,
    history: scopes.includes("history") ? full(reason) : null,
    reuseFiles: null,
    label: "",
    historyBase: null,
  };
}

/**
 * Decides, area by area, whether this scan may build on the stored one. Every doubt is a full
 * scan: the function only returns an incremental area when nothing it knows can make the stored
 * data stale. The per-file reuse is checked again against each file's content hash.
 */
export async function planIncremental(params: {
  dependencies: IncrementalDependencies;
  outcome: AuthorizationOutcome;
  requestedScopes: readonly ScanScope[];
  projectRoot: string;
  /** The commit this scan reads (the revision the gate verified). */
  revision: string | null;
  configFingerprint: string | null;
  signal?: AbortSignal;
}): Promise<IncrementalPlan> {
  const { dependencies, requestedScopes } = params;
  if (dependencies.forceFull === true) return allFull("requested_full", requestedScopes);
  let loaded: IncrementalBaseLoad;
  try {
    loaded = await dependencies.loadBase(params.outcome, requestedScopes);
  } catch {
    return allFull("store_unavailable", requestedScopes);
  }
  if (loaded.kind === "none") return allFull(loaded.reason, requestedScopes);
  const { result, state } = loaded.base;
  const basedOn = { scanId: result.scanId, revision: result.target.revision };
  const fail = (reason: IncrementalFullReason) => allFull(reason, requestedScopes, null);

  if (!sameScopes(result.requestedScopes, requestedScopes)) return fail("scopes_changed");
  if (result.tool.version !== PGARD_VERSION) return fail("tool_changed");
  if (result.advisoryDb.version !== null || result.advisoryDb.updatedAt !== null) {
    return fail("tool_changed");
  }
  if (state === null) {
    const omitted = loaded.base.stateOmitted;
    return fail(
      omitted === "too_large"
        ? "previous_state_too_large"
        : omitted === "rejected"
          ? "previous_state_rejected"
          : "no_saved_state",
    );
  }
  if (state.analysisKey !== computeAnalysisKey()) return fail("tool_changed");
  if (state.analyzerHash !== ANALYZER_HASH) return fail("analyzer_changed");
  if (state.code !== null && !entriesAreStructurallySound(state.code)) {
    return fail("previous_unreadable");
  }
  if (state.configHash !== params.configFingerprint) return fail("config_changed");
  if (blockingCoverage(result) !== null) return fail("previous_incomplete");
  if (unclassifiedRules().length > 0) return fail("rules_unclassified");
  const baseRevision = result.target.revision;
  if (baseRevision === null || params.revision === null) return fail("git_failed");
  if (!(await isAncestorCommit(params.projectRoot, baseRevision, params.revision))) {
    return fail("head_not_ancestor");
  }

  // Paths that differ between the stored commit and this one are never reused, even when a
  // file's content happens to match the stored hash. Uncommitted and untracked files are covered
  // by the content hash of every file the walk finds (the walk applies `exclude`).
  let changed: Set<string>;
  try {
    changed = await listChangedPaths(
      params.projectRoot,
      baseRevision,
      params.revision,
      params.signal,
    );
  } catch {
    if (params.signal?.aborted) throw params.signal.reason;
    return fail("git_failed");
  }

  let reuseFiles: Map<string, CachedSourceFile> | null = null;
  let code: AreaPlan | null = null;
  if (requestedScopes.includes("code")) {
    if (state.code === null) {
      code = full("no_saved_state");
    } else {
      const agreeing = entriesAgreeingWithResult(state.code, result);
      reuseFiles = new Map(
        agreeing.filter((file) => !changed.has(file.path)).map((file) => [file.path, file]),
      );
      code = INCREMENTAL_AREA;
    }
  }
  let history: AreaPlan | null = null;
  let historyBase: HistoryIncrementalBase | null = null;
  if (requestedScopes.includes("history")) {
    historyBase = historyBaseOf(result, baseRevision);
    history = historyBase === null ? full("no_saved_state") : INCREMENTAL_AREA;
  }
  return {
    base: basedOn,
    code,
    history,
    reuseFiles,
    label: result.scanId.slice(0, 8),
    historyBase,
  };
}
