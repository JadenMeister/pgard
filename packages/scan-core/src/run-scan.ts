import { randomUUID } from "node:crypto";
import path from "node:path";
import {
  SCAN_SCOPES,
  SCHEMA_VERSION,
  deriveOverallStatus,
  type AdvisoryDbInfo,
  type AnalyzerOutput,
  type AuthorizationSummary,
  type ConfirmedWebTarget,
  type Coverage,
  type Finding,
  type ScanRequest,
  type ScanResult,
  type ScanScope,
} from "@pgard/findings";
import {
  AUTHORIZATION_CHECK_ORDER,
  authorizeProject,
  isAuthorizationAllowed,
  type AuthorizationOutcome,
} from "@pgard/policy";
import { createDefaultAnalyzers } from "./analyzers.js";
import { normalizeFindingPaths } from "./paths.js";
import {
  ScanCancelledError,
  type AnalyzerContext,
  type LocalAnalyzerOutput,
  type ScanDependencies,
  type ScanProgressEvent,
} from "./types.js";
import { PGARD_VERSION } from "./version.js";

export class ScanRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanRequestError";
  }
}

const EMPTY_ADVISORY_DB: AdvisoryDbInfo = { version: null, updatedAt: null };

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

/** Forces analyzer output into the stage's scope so a scanner cannot report for another area. */
function normalizeAnalyzerOutput(
  scope: ScanScope,
  output: AnalyzerOutput,
  projectRoot: string,
): AnalyzerOutput {
  const coverage = output.coverage.map((entry) => ({ ...entry, scope }));
  const findings = output.findings.map((finding) => {
    const sources: ScanScope[] = finding.sources.length > 0 ? [...finding.sources] : [scope];
    if (!sources.includes(scope)) {
      sources.push(scope);
    }
    return normalizeFindingPaths({ ...finding, sources }, projectRoot);
  });
  return {
    findings,
    coverage:
      coverage.length > 0 ? coverage : [scopeCoverage(scope, "partial", "No coverage reported.")],
  };
}

/**
 * Orchestrates one scan: runs the authorization gate (always, never cached), then the requested
 * analyzers only if the decision is `allowed`. Analyzer failures mark that area `not_tested`
 * while keeping other results. Rejects only with `ScanRequestError` (invalid request) or
 * `ScanCancelledError` (aborted); internal errors produce `overallStatus: "failed"`.
 */
export async function runScan(request: ScanRequest, deps: ScanDependencies): Promise<ScanResult> {
  const requestedScopes = validateRequest(request);
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
  const isWebTargetValid =
    requestedScopes.includes("web") && isValidConfirmedWebTarget(request.webTarget);

  const finish = (fields: {
    authorization: AuthorizationSummary;
    outcome: AuthorizationOutcome | null;
    coverage: Coverage[];
    findings: Finding[];
    advisoryDb: AdvisoryDbInfo;
    overallStatus?: ScanResult["overallStatus"];
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
        decision: fields.authorization.decision,
        requestedScopes,
        coverage: fields.coverage,
      }),
    target: {
      repo: fields.outcome?.repo ?? null,
      revision: fields.outcome?.revision ?? null,
      webOrigin: isWebTargetValid && request.webTarget ? request.webTarget.origin : null,
    },
    authorization: fields.authorization,
    coverage: fields.coverage,
    findings: sortFindings(fields.findings),
    advisoryDb: fields.advisoryDb,
  });

  throwIfCancelled(deps.signal);
  emit({
    stage: "authorization",
    status: "started",
    message: "Verifying repository authorization.",
  });
  let outcome: AuthorizationOutcome;
  try {
    outcome = await authorizeProject(request.projectRoot, deps.authorization);
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
      advisoryDb: EMPTY_ADVISORY_DB,
      overallStatus: "failed",
    });
  }
  throwIfCancelled(deps.signal);

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
      advisoryDb: EMPTY_ADVISORY_DB,
    });
  }
  emit({ stage: "authorization", status: "completed", message: "Authorization verified." });

  const analyzers = { ...createDefaultAnalyzers(), ...deps.analyzers };
  const context: AnalyzerContext = {
    projectRoot: request.projectRoot,
    env,
    now,
    ...(deps.signal ? { signal: deps.signal } : {}),
  };
  const coverage: Coverage[] = [];
  const findings: Finding[] = [];
  let advisoryDb = EMPTY_ADVISORY_DB;

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
      const normalized = normalizeAnalyzerOutput(scope, output, request.projectRoot);
      coverage.push(...normalized.coverage);
      findings.push(...normalized.findings);
      if (scope === "code" && output.advisoryDb) {
        advisoryDb = output.advisoryDb;
      }
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

  return finish({
    authorization: outcome.summary,
    outcome,
    coverage,
    findings,
    advisoryDb,
  });
}
