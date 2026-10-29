import { randomUUID } from "node:crypto";
import path from "node:path";
import {
  SCAN_SCOPES,
  SCHEMA_VERSION,
  applyFindingContext,
  applySuppressions,
  compilePathMatcher,
  computeStandardsCoverage,
  deriveOverallStatus,
  mergeFindings,
  redactEvidence,
  type AdvisoryDbInfo,
  type AnalyzerOutput,
  type AuthorizationSummary,
  type ConfirmedWebTarget,
  type Coverage,
  type Finding,
  type IncrementalAreaInfo,
  type IncrementalFullReason,
  type IncrementalInfo,
  type IncrementalState,
  type KnownScanBasisReason,
  type PathMatcher,
  type RuleStat,
  type StandardsRule,
  type ScanRequest,
  type ScanResult,
  type ScanScope,
  type SuppressionSummary,
} from "@pgard/findings";
import {
  AUTHORIZATION_CHECK_ORDER,
  AUTHORIZATION_REASON_MAX_LENGTH,
  authorizeProject,
  isAuthorizationAllowed,
  type AuthorizationOutcome,
} from "@pgard/policy";
import { createDefaultAnalyzers } from "./analyzers.js";
import { ANALYZER_HASH } from "./analyzer-hash.js";
import {
  computeAnalysisKey,
  fingerprintConfig,
  planIncremental,
  type IncrementalPlan,
} from "./incremental.js";
import { attachFixSuggestions, CONFIG_BUDGET_NOTE } from "@pgard/source-analysis";
import { normalizeFindingPaths } from "./paths.js";
import {
  describeProjectConfig,
  loadProjectConfig,
  type ProjectConfigLoad,
} from "./project-config.js";
import {
  ScanCancelledError,
  type AnalyzerContext,
  type LocalAnalyzer,
  type LocalAnalyzerOutput,
  type ScanDependencies,
  type ScanProgressEvent,
} from "./types.js";
import { listSupportedRules } from "./rules.js";
import { PGARD_VERSION } from "./version.js";
import { scanWorkingTreeSecrets } from "./working-tree-secrets.js";

export class ScanRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanRequestError";
  }
}

/**
 * PGARD ships no vulnerability database (OSV data is user-downloaded and matched locally). The JSON v1 `advisoryDb` field is kept
 * for compatibility and is always empty.
 */
const NO_ADVISORY_DB: AdvisoryDbInfo = { version: null, updatedAt: null };

function validateRequest(request: ScanRequest): ScanScope[] {
  if (typeof request.projectRoot !== "string" || !path.isAbsolute(request.projectRoot)) {
    throw new ScanRequestError("projectRoot must be an absolute path.");
  }
  if (!Array.isArray(request.scopes) || request.scopes.length === 0) {
    throw new ScanRequestError("At least one scan scope is required.");
  }
  for (const scope of request.scopes) {
    if (!SCAN_SCOPES.includes(scope)) {
      throw new ScanRequestError(`Unknown scan scope: ${String(scope)}`);
    }
  }
  // Canonical order keeps results identical regardless of how a launcher listed scopes.
  return SCAN_SCOPES.filter((scope) => request.scopes.includes(scope));
}

/** A web target is usable only if it is a user-confirmed numeric loopback origin. */
export function isValidConfirmedWebTarget(target: ConfirmedWebTarget | null): boolean {
  if (target === null || target.confirmedByUser !== true) {
    return false;
  }
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
    return false;
  }
  return target.origin === `http://127.0.0.1:${target.port}`;
}

function scopeCoverage(
  scope: ScanScope,
  status: Coverage["status"],
  note: string | null,
): Coverage {
  return { area: scope, scope, status, ruleIds: [], note };
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new ScanCancelledError();
  }
}

function sortFindings(findings: Finding[]): Finding[] {
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  return [...findings].sort(
    (a, b) =>
      severityRank[a.severity] - severityRank[b.severity] ||
      a.ruleId.localeCompare(b.ruleId) ||
      (a.location.path ?? a.location.url ?? "").localeCompare(
        b.location.path ?? b.location.url ?? "",
      ) ||
      (a.location.line ?? 0) - (b.location.line ?? 0) ||
      a.id.localeCompare(b.id),
  );
}

function unverifiedSummary(reason: string): AuthorizationSummary {
  return {
    decision: "blocked",
    checks: AUTHORIZATION_CHECK_ORDER.map((id) => ({ id, status: "unverifiable", reason })),
  };
}

/**
 * Forces analyzer output into the stage's scope so a scanner cannot report for another area, and
 * marks findings in test, fixture or vendored code (every source: code, dependencies, history,
 * web) so all frontends group them the same way.
 */
function normalizeAnalyzerOutput(
  scope: ScanScope,
  output: AnalyzerOutput,
  projectRoot: string,
  testPaths: PathMatcher | null,
): AnalyzerOutput & { configTestFindings: number; ruleStats: RuleStat[] } {
  let configTestFindings = 0;
  const coverage = output.coverage.map((entry) => ({ ...entry, scope }));
  const findings = output.findings.map((finding) => {
    const sources: ScanScope[] = finding.sources.length > 0 ? [...finding.sources] : [scope];
    if (!sources.includes(scope)) {
      sources.push(scope);
    }
    const normalized = normalizeFindingPaths({ ...finding, sources }, projectRoot);
    const context = applyFindingContext(normalized);
    if (testPaths === null) return context;
    // `testDirectories` can only add the test context, never remove one; count what it added.
    const configured = applyFindingContext(normalized, {
      isConfiguredTestPath: (filePath) => testPaths.matches(filePath),
    });
    if (configured.context !== context.context) configTestFindings += 1;
    return configured;
  });
  const finalCoverage =
    coverage.length > 0 ? coverage : [scopeCoverage(scope, "partial", "No coverage reported.")];
  return {
    configTestFindings,
    findings,
    coverage: finalCoverage,
    ruleStats: normalizeRuleStats(scope, output, finalCoverage),
  };
}

const UNMEASURED = "The analyzer did not report how many targets this rule examined.";

/**
 * Rule stats are tied to the coverage the same output reports: one row per rule that an area
 * lists and that ran (`completed` or `partial`). A row the analyzer sent for a rule or area that
 * coverage does not list is dropped, the area's status always comes from coverage, and a rule
 * the analyzer sent no row for gets an explicit unknown count instead of a guess.
 */
function normalizeRuleStats(
  scope: ScanScope,
  output: AnalyzerOutput,
  coverage: readonly Coverage[],
): RuleStat[] {
  const reported = output.ruleStats ?? [];
  const stats: RuleStat[] = [];
  for (const entry of coverage) {
    if (entry.status !== "completed" && entry.status !== "partial") continue;
    for (const ruleId of new Set(entry.ruleIds)) {
      const row = reported.find((stat) => stat.ruleId === ruleId && stat.area === entry.area);
      stats.push(
        row === undefined
          ? {
              ruleId,
              area: entry.area,
              scope,
              status: entry.status,
              targets: [{ unit: "unknown", examined: null, reason: UNMEASURED }],
              // Findings carry no area, so the count is only known when the rule ran in one area.
              findings: output.findings.filter((finding) => finding.ruleId === ruleId).length,
            }
          : { ...row, scope, status: entry.status },
      );
    }
  }
  return stats;
}

/**
 * Orchestrates one scan: runs the authorization gate (always, never cached), then the requested
 * analyzers only if the decision is `allowed`. Analyzer failures mark that area `not_tested`
 * while keeping other results. Rejects only with `ScanRequestError` (invalid request) or
 * `ScanCancelledError` (aborted); internal errors produce `overallStatus: "failed"`.
 */
export async function runScan(request: ScanRequest, deps: ScanDependencies): Promise<ScanResult> {
  return executeScan(request, deps, "authorized");
}

/** Fixed reason on every check of a code-only result: the gate did not run. */
export const CODE_ONLY_CHECK_REASON =
  "Not checked: this was a code-only scan of the files on this computer. No authorization was proven.";

/**
 * PROTOTYPE (#414, not used by the CLI): a code-only scan of the files in `projectRoot` without
 * the authorization gate. Only the `code` scope runs (source rules and dependencies against the
 * OSV data already on disk); no Git object is read, nothing is sent over the network, no
 * incremental state is offered and nothing is stored. The result never claims authorization:
 * `authorization.decision` is `blocked` and every check is `unverifiable` with
 * `CODE_ONLY_CHECK_REASON`; `overallStatus` comes from the code coverage alone. Git history and
 * web checks are refused here (`ScanRequestError`): they keep the full gate of `runScan`.
 */
export async function runCodeOnlyScan(
  request: Pick<ScanRequest, "projectRoot"> & {
    /**
     * Why this scan is code-only (`scanBasis.reason`, default `not_checked`): for example
     * `no_github_remote` or `not_a_git_repository` when the launcher knows the folder has no
     * GitHub repository to verify, or `no_approval` after the gate blocked.
     */
    reason?: KnownScanBasisReason;
  },
  deps: Omit<
    ScanDependencies,
    "authorization" | "webScanner" | "webRules" | "incremental" | "onAuthorization"
  >,
): Promise<ScanResult> {
  // The built-in code analyzer plus a secrets pass over the files on disk (secrets are otherwise
  // found by the history scope, which a code-only scan never runs). An injected analyzer (tests)
  // replaces both.
  const defaultCode = createDefaultAnalyzers().code;
  const code: LocalAnalyzer =
    deps.analyzers?.code ??
    (async (context) => {
      const [base, secrets] = await Promise.all([
        defaultCode(context),
        scanWorkingTreeSecrets(context),
      ]);
      return {
        ...base,
        findings: [...base.findings, ...secrets.findings],
        coverage: [...base.coverage, ...secrets.coverage],
      };
    });
  return executeScan(
    { projectRoot: request.projectRoot, scopes: ["code"], webTarget: null },
    {
      ...deps,
      analyzers: { ...deps.analyzers, code },
      authorization: { getGitHubSession: refuseGitHubSession },
    },
    "code_only",
    request.reason ?? "not_checked",
  );
}

/** Never called (the code-only path skips the gate); refuses if it ever were. */
const refuseGitHubSession = Object.assign(
  async (): Promise<never> => {
    throw new Error("A code-only scan never signs in to GitHub.");
  },
  { invalidate: () => undefined, signOut: () => undefined, existing: async () => null },
);

async function executeScan(
  request: ScanRequest,
  deps: ScanDependencies,
  mode: "authorized" | "code_only",
  codeOnlyReason: KnownScanBasisReason = "not_checked",
): Promise<ScanResult> {
  const requestedScopes = validateRequest(request);
  if (mode === "code_only" && requestedScopes.some((scope) => scope !== "code")) {
    throw new ScanRequestError("A code-only scan runs the code scope only.");
  }
  // Without the web rules the standards map would not know what the web scanner can check and
  // would claim more than it can support, so a launcher that injects a scanner must name them.
  if (deps.webScanner !== undefined && deps.webRules === undefined) {
    throw new TypeError("ScanDependencies.webRules is required when webScanner is set.");
  }
  const now = deps.now ?? (() => new Date());
  const scanId = (deps.createScanId ?? randomUUID)();
  const startedAt = now().toISOString();
  const env = deps.env ?? process.env;
  const emit = (event: ScanProgressEvent) => {
    try {
      deps.onProgress?.(event);
    } catch {
      // Progress rendering must never affect scan results.
    }
  };
  const catalog: StandardsRule[] = [
    ...listSupportedRules(),
    ...(deps.webRules ?? []).map((rule) => ({
      id: rule.id,
      scope: "web" as const,
      metadata: rule.metadata,
    })),
  ];
  const isWebTargetValid =
    requestedScopes.includes("web") && isValidConfirmedWebTarget(request.webTarget);

  const finish = (fields: {
    authorization: AuthorizationSummary;
    outcome: AuthorizationOutcome | null;
    coverage: Coverage[];
    findings: Finding[];
    suppressions?: SuppressionSummary | null;
    ruleStats?: RuleStat[];
    incremental?: IncrementalInfo | null;
    overallStatus?: ScanResult["overallStatus"];
    /** Why an authorized-mode scan is not verified; `no_approval` unless the gate failed. */
    basisReason?: KnownScanBasisReason;
  }): ScanResult => ({
    schemaVersion: SCHEMA_VERSION,
    scanId,
    startedAt,
    finishedAt: now().toISOString(),
    tool: { name: "pgard", version: PGARD_VERSION },
    requestedScopes,
    overallStatus:
      fields.overallStatus ??
      deriveOverallStatus({
        // A code-only result reports how much of the code scope ran; it is never `allowed`.
        decision: mode === "code_only" ? "allowed" : fields.authorization.decision,
        requestedScopes,
        coverage: fields.coverage,
      }),
    target: {
      repo: fields.outcome?.repo ?? null,
      revision: fields.outcome?.revision ?? null,
      webOrigin: isWebTargetValid && request.webTarget ? request.webTarget.origin : null,
    },
    authorization: {
      ...fields.authorization,
      checks: fields.authorization.checks.map((check) => ({
        ...check,
        reason: redactEvidence(check.reason, {
          projectRoot: request.projectRoot,
          maxLength: AUTHORIZATION_REASON_MAX_LENGTH,
        }),
      })),
    },
    // Notes can come from any analyzer (including the injected web scanner): redact them
    // exactly like evidence.
    coverage: fields.coverage.map((entry) => ({
      ...entry,
      note:
        entry.note === null
          ? null
          : redactEvidence(entry.note, { projectRoot: request.projectRoot }),
    })),
    findings: sortFindings(mergeFindings(fields.findings)),
    advisoryDb: { ...NO_ADVISORY_DB },
    ...(fields.suppressions ? { suppressions: fields.suppressions } : {}),
    ruleStats: fields.ruleStats ?? [],
    standardsCoverage: computeStandardsCoverage({
      rules: catalog,
      coverage: fields.coverage,
      ruleStats: fields.ruleStats ?? [],
    }),
    ...(fields.incremental ? { incremental: fields.incremental } : {}),
    scanBasis:
      mode === "code_only"
        ? { mode: "code_only", authorization: "not_verified", reason: codeOnlyReason }
        : fields.authorization.decision === "allowed"
          ? { mode: "authorized", authorization: "verified", reason: null }
          : {
              mode: "authorized",
              authorization: "not_verified",
              reason: fields.basisReason ?? "no_approval",
            },
  });

  throwIfCancelled(deps.signal);
  let outcome: AuthorizationOutcome;
  if (mode === "code_only") {
    outcome = { summary: unverifiedSummary(CODE_ONLY_CHECK_REASON), repo: null, revision: null };
    emit({
      stage: "authorization",
      status: "skipped",
      message: "Code-only scan: authorization was not checked.",
    });
  } else {
    emit({
      stage: "authorization",
      status: "started",
      message: "Verifying repository authorization.",
    });
    try {
      outcome = await authorizeProject(request.projectRoot, {
        ...deps.authorization,
        ...(request.expectedRepo ? { expectedRepo: request.expectedRepo } : {}),
        ...(deps.signal ? { signal: deps.signal } : {}),
      });
    } catch {
      throwIfCancelled(deps.signal);
      emit({ stage: "authorization", status: "failed", message: "Authorization check failed." });
      return finish({
        authorization: unverifiedSummary(
          "Authorization could not be completed due to an internal error.",
        ),
        outcome: null,
        coverage: SCAN_SCOPES.map((scope) =>
          requestedScopes.includes(scope)
            ? scopeCoverage(scope, "not_tested", "Authorization could not be completed.")
            : scopeCoverage(scope, "not_selected", null),
        ),
        findings: [],
        overallStatus: "failed",
        basisReason: "check_failed",
      });
    }
    throwIfCancelled(deps.signal);
    try {
      deps.onAuthorization?.(outcome);
    } catch {
      // Display hooks must never affect scan results.
    }

    if (!isAuthorizationAllowed(outcome)) {
      emit({
        stage: "authorization",
        status: "failed",
        message: "Scan blocked by authorization gate.",
      });
      return finish({
        authorization: { ...outcome.summary, decision: "blocked" },
        outcome,
        coverage: SCAN_SCOPES.map((scope) =>
          requestedScopes.includes(scope)
            ? scopeCoverage(scope, "not_tested", "Blocked by the authorization gate.")
            : scopeCoverage(scope, "not_selected", null),
        ),
        findings: [],
      });
    }
    emit({ stage: "authorization", status: "completed", message: "Authorization verified." });
  }

  // The repository's own config is untrusted data: validated strictly, never able to change
  // authorization (which already ran), and an invalid one is ignored as a whole.
  const configLoad: ProjectConfigLoad = await loadProjectConfig(request.projectRoot).catch(
    (): ProjectConfigLoad => ({
      state: "invalid",
      problems: ["pgard.config.json could not be read"],
    }),
  );
  throwIfCancelled(deps.signal);
  const projectConfig = configLoad.state === "loaded" ? configLoad.config : null;
  const testPaths =
    projectConfig !== null && projectConfig.testDirectories.length > 0
      ? compilePathMatcher(projectConfig.testDirectories)
      : null;
  const analyzers = { ...createDefaultAnalyzers(), ...deps.analyzers };
  const configHash = fingerprintConfig(configLoad);
  // Web is never incremental: it is always scanned live. Only the local scopes can reuse.
  const plan: IncrementalPlan | null =
    mode === "authorized" &&
    deps.incremental !== undefined &&
    (requestedScopes.includes("code") || requestedScopes.includes("history"))
      ? await planIncremental({
          dependencies: deps.incremental,
          outcome,
          requestedScopes,
          projectRoot: request.projectRoot,
          revision: outcome.revision,
          configFingerprint: configHash,
          ...(deps.signal ? { signal: deps.signal } : {}),
        })
      : null;
  throwIfCancelled(deps.signal);
  const context: AnalyzerContext = {
    ...(plan?.code?.mode === "incremental" && plan.reuseFiles !== null
      ? { sourceReuse: { files: plan.reuseFiles, label: plan.label } }
      : {}),
    ...(plan?.history?.mode === "incremental" && plan.historyBase !== null
      ? { historyIncremental: plan.historyBase }
      : {}),
    projectConfig,
    advisoryDataDir: deps.advisoryDataDir ?? null,
    projectRoot: request.projectRoot,
    revision: outcome.revision,
    env,
    now,
    ...(deps.signal ? { signal: deps.signal } : {}),
  };
  const coverage: Coverage[] = [];
  const findings: Finding[] = [];
  // The `source:config` entry is written once the suppressions are applied (it counts them).
  let configIndex = -1;
  let configTestFindings = 0;
  let configBudgetWarning: string | null = null;
  const ruleStats: RuleStat[] = [];
  const outputs: Partial<Record<"code" | "history", LocalAnalyzerOutput>> = {};

  for (const scope of SCAN_SCOPES) {
    if (!requestedScopes.includes(scope)) {
      coverage.push(scopeCoverage(scope, "not_selected", null));
      continue;
    }
    throwIfCancelled(deps.signal);

    if (scope === "web") {
      if (!isWebTargetValid || !request.webTarget) {
        emit({ stage: "web", status: "skipped", message: "No confirmed local web target." });
        coverage.push(
          scopeCoverage("web", "not_tested", "No confirmed local web target was selected."),
        );
        continue;
      }
      if (!deps.webScanner) {
        emit({ stage: "web", status: "skipped", message: "Web scanner unavailable." });
        coverage.push(scopeCoverage("web", "not_tested", "The web scanner is not available."));
        continue;
      }
    }

    emit({ stage: scope, status: "started", message: `Running ${scope} analysis.` });
    try {
      let output: LocalAnalyzerOutput;
      if (scope === "web" && deps.webScanner && request.webTarget) {
        output = await deps.webScanner(request.webTarget, {
          ...(deps.signal ? { signal: deps.signal } : {}),
          onProgress: (web) =>
            emit({ stage: "web", status: "started", message: "Checking local web pages.", web }),
        });
      } else {
        const analyzer = analyzers[scope as "code" | "history"];
        output = await analyzer(context);
      }
      throwIfCancelled(deps.signal);
      if (scope === "code" || scope === "history") outputs[scope] = output;
      // Configured test directories apply to source code only: a secret in history stays a
      // regular finding whatever the project calls the directory.
      const normalized = normalizeAnalyzerOutput(
        scope,
        output,
        request.projectRoot,
        scope === "code" ? testPaths : null,
      );
      if (scope === "code") {
        // The source scan reports a `source:config` entry only when its own pattern matching ran
        // out of work budget; merge it with ours so the area appears once.
        const budgetEntry = normalized.coverage.find((entry) => entry.area === "source:config");
        const budgetWarning =
          budgetEntry?.note ?? (testPaths?.exhausted === true ? CONFIG_BUDGET_NOTE : null);
        coverage.push(...normalized.coverage.filter((entry) => entry.area !== "source:config"));
        configTestFindings = normalized.configTestFindings;
        configBudgetWarning = budgetWarning;
        if (configLoad.state !== "absent") {
          configIndex = coverage.length;
          coverage.push(scopeCoverage("code", "completed", null));
        }
      } else if (scope === "history" && plan !== null && output.history?.mode === "incremental") {
        coverage.push(...describeReusedHistory(normalized.coverage, output.history, plan.label));
      } else {
        coverage.push(...normalized.coverage);
      }
      findings.push(...normalized.findings);
      ruleStats.push(...normalized.ruleStats);
      emit({ stage: scope, status: "completed", message: `Finished ${scope} analysis.` });
    } catch (error) {
      if (error instanceof ScanCancelledError || deps.signal?.aborted) {
        throw new ScanCancelledError();
      }
      emit({ stage: scope, status: "failed", message: `The ${scope} analysis failed.` });
      coverage.push(
        scopeCoverage(
          scope,
          "not_tested",
          `The ${scope} analyzer failed; results for this area are missing.`,
        ),
      );
    }
  }

  // Suppressions only change where a finding is listed (`finding.suppression`); nothing is
  // dropped, and neither the coverage nor the overall status depends on them.
  const suppressed = applySuppressions(findings, projectConfig?.suppressions ?? [], now());
  // Suggested fixes (JSON v1.6) are read-only and optional: a failure here never affects the scan.
  try {
    suppressed.findings = await attachFixSuggestions(suppressed.findings, request.projectRoot, {
      ...(deps.signal ? { signal: deps.signal } : {}),
    });
  } catch {
    // The findings stay without a suggested fix.
  }
  if (configIndex !== -1) {
    const configCoverage = describeProjectConfig(
      configLoad,
      configTestFindings,
      configBudgetWarning,
      suppressed.summary,
    );
    if (configCoverage !== null) coverage[configIndex] = configCoverage;
  }

  const incremental = plan === null ? null : describeIncremental(plan, outputs);
  if (deps.incremental?.onState !== undefined && plan !== null) {
    const codeCache = outputs.code?.sourceCache;
    // State is only handed over when it is complete: a code scope that failed has none.
    if (codeCache !== undefined || !requestedScopes.includes("code")) {
      const state: IncrementalState = {
        format: 1,
        analysisKey: computeAnalysisKey(),
        analyzerHash: ANALYZER_HASH,
        configHash,
        code: codeCache ?? null,
      };
      try {
        deps.incremental.onState(state, scanId);
      } catch {
        // Storing the state must never affect the scan.
      }
    }
  }

  return finish({
    authorization: outcome.summary,
    outcome,
    coverage,
    findings: suppressed.findings,
    suppressions: suppressed.summary,
    ruleStats,
    incremental,
  });
}

/** Says in the history coverage note which commits were reused and how many were read. */
function describeReusedHistory(
  entries: Coverage[],
  history: NonNullable<LocalAnalyzerOutput["history"]>,
  label: string,
): Coverage[] {
  return entries.map((entry) =>
    entry.area === "history:commits" && entry.note !== null
      ? {
          ...entry,
          note: `${entry.note} Only ${history.commitsScanned} new commit(s) were read; findings of ${history.commitsReused} earlier commit(s) were reused from scan ${label}.`,
        }
      : entry,
  );
}

function areaInfo(
  planned: IncrementalPlan["code"],
  isIncremental: boolean,
  downgrade: IncrementalFullReason,
): IncrementalAreaInfo | null {
  if (planned === null) return null;
  if (planned.mode === "full") return { mode: "full", reason: planned.reason };
  return isIncremental
    ? { mode: "incremental", reason: null }
    : { mode: "full", reason: downgrade };
}

/** The `incremental` field: what each local area reused (or why it was scanned in full). */
function describeIncremental(
  plan: IncrementalPlan,
  outputs: Partial<Record<"code" | "history", LocalAnalyzerOutput>>,
): IncrementalInfo {
  const codeOut = outputs.code;
  const historyOut = outputs.history;
  // An area that was planned as incremental counts as one only when the analyzer says it reused.
  const code = areaInfo(plan.code, codeOut?.sourceReuse !== undefined, "no_saved_state");
  const history = areaInfo(
    plan.history,
    historyOut?.history?.mode === "incremental",
    historyOut?.history === undefined ? "no_saved_state" : "history_changed",
  );
  const used = code?.mode === "incremental" || history?.mode === "incremental";
  return {
    used,
    reason: code?.reason ?? history?.reason ?? null,
    basedOn: used ? plan.base : null,
    filesRescanned: codeOut?.sourceReuse?.rescanned ?? null,
    filesReused: codeOut?.sourceReuse?.reused ?? null,
    commitsScanned: historyOut?.history?.commitsScanned ?? null,
    commitsReused: historyOut?.history?.commitsReused ?? null,
    code,
    history,
  };
}
