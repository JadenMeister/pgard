import { compilePathMatcher, type Coverage, type Finding } from "@pgard/findings";
import {
  GitCommandError,
  INCOMPLETE_SKIP_REASONS,
  addedLineNumbers,
  readStagedChanges,
  scanStagedSecrets,
  type GitRunner,
  type StagedSkip,
} from "@pgard/git-history";
import { analyzeStagedSource } from "@pgard/source-analysis";
import type { LocalAnalyzer } from "./types.js";

/** Time cap for reading and analysing the staged changes (the authorization check is extra). */
export const STAGED_SCAN_BUDGET_MS = 2_000;

export const STAGED_COVERAGE_AREA = "staged:changes";
const RULE_IDS = ["PG-SECRET-001", "PG-SECRET-002"];

/** What the staged scan did, for the command to print. Counts and paths only; no content. */
export interface StagedScanReport {
  /** Staged files that differ from HEAD and were read as text. */
  scanned: number;
  /** Files the file-local source rules ran on. */
  sourceChecked: number;
  /** Text files of a kind the source rules do not read (checked for secrets only). */
  secretsOnly: number;
  /** Files left out of the source rules by `exclude` in pgard.config.json (secrets still checked). */
  excluded: number;
  /** Files not read, with the reason. */
  skipped: StagedSkip[];
  /** Source-rule runs that did not happen because the time cap was reached. */
  sourceSkippedForTime: number;
  deleted: number;
  unchanged: number;
  /** Findings on lines this commit does not change; not reported. */
  preexisting: number;
  bytesRead: number;
  elapsedMs: number;
  /** Set when the staged changes could not be read at all. */
  failure: { kind: "timeout" | "error"; message: string } | null;
}

export interface StagedScanSettings {
  /** The index the hook is committing (`GIT_INDEX_FILE`), already checked to be inside `.git`. */
  indexFile?: string;
  budgetMs?: number;
  runner?: GitRunner;
  now?: () => number;
  onReport?: (report: StagedScanReport) => void;
}

const SKIP_TEXT: Record<StagedSkip["reason"], string> = {
  binary: "binary",
  symlink: "symbolic link",
  submodule: "submodule",
  too_large: "over the size limit",
  file_limit: "over the file limit",
  byte_budget: "over the total size limit",
  time_budget: "time cap reached",
  unmerged: "unresolved merge conflict",
  unreadable: "could not be read",
};

function countBy(skipped: readonly StagedSkip[], reason: StagedSkip["reason"]): number {
  return skipped.filter((item) => item.reason === reason).length;
}

/** The note of the `staged:changes` coverage area: what was and was not looked at. */
export function describeStagedReport(report: StagedScanReport): string {
  if (report.failure !== null) return report.failure.message;
  const parts = [
    `${report.scanned} staged file(s) scanned for secrets, ${report.sourceChecked} of them also with the file-local source rules`,
  ];
  if (report.secretsOnly > 0) parts.push(`${report.secretsOnly} not a source type, secrets only`);
  if (report.excluded > 0) {
    parts.push(`${report.excluded} excluded from source rules by pgard.config.json`);
  }
  for (const reason of Object.keys(SKIP_TEXT) as StagedSkip["reason"][]) {
    const count = countBy(report.skipped, reason);
    if (count > 0) parts.push(`${count} ${SKIP_TEXT[reason]}, not scanned`);
  }
  if (report.sourceSkippedForTime > 0) {
    parts.push(`${report.sourceSkippedForTime} not checked with source rules (time cap)`);
  }
  return `${parts.join("; ")}.`;
}

/** True when part of the staged change was not examined and not by design (binary files are by design). */
export function isStagedReportIncomplete(report: StagedScanReport): boolean {
  return (
    report.failure !== null ||
    report.sourceSkippedForTime > 0 ||
    report.skipped.some((item) => INCOMPLETE_SKIP_REASONS.has(item.reason))
  );
}

/**
 * The `code` analyzer of a pre-commit run: reads the staged changes from the index and checks
 * the lines the commit adds or changes. It replaces the whole-project code scan, so it runs only
 * after the authorization gate allowed (the scan's own gate, unchanged). It never throws for a
 * Git failure: that is reported as an area that could not run (`not_tested`), never as "nothing
 * found".
 */
export function createStagedAnalyzer(settings: StagedScanSettings = {}): LocalAnalyzer {
  return async (context) => {
    const now = settings.now ?? Date.now;
    const startedAt = now();
    const budgetMs = settings.budgetMs ?? STAGED_SCAN_BUDGET_MS;
    const deadline = startedAt + budgetMs;
    const report: StagedScanReport = {
      scanned: 0,
      sourceChecked: 0,
      secretsOnly: 0,
      excluded: 0,
      skipped: [],
      sourceSkippedForTime: 0,
      deleted: 0,
      unchanged: 0,
      preexisting: 0,
      bytesRead: 0,
      elapsedMs: 0,
      failure: null,
    };
    const findings: Finding[] = [];
    try {
      const changes = await readStagedChanges(context.projectRoot, {
        ...(context.signal ? { signal: context.signal } : {}),
        ...(settings.indexFile ? { indexFile: settings.indexFile } : {}),
        ...(settings.runner ? { runner: settings.runner } : {}),
        deadline,
        now,
      });
      report.skipped = changes.skipped;
      report.deleted = changes.deleted;
      report.unchanged = changes.unchanged;
      report.bytesRead = changes.bytesRead;
      report.scanned = changes.files.length;
      // Secrets first: they are cheap and are never cut by the time cap.
      const secrets = scanStagedSecrets(changes.files);
      findings.push(...secrets.findings);
      report.preexisting += secrets.preexisting;
      const exclude =
        context.projectConfig !== null && context.projectConfig.exclude.length > 0
          ? compilePathMatcher(context.projectConfig.exclude)
          : null;
      for (const file of changes.files) {
        if (exclude?.matches(file.path) === true) {
          report.excluded += 1;
          continue;
        }
        if (now() >= deadline) {
          report.sourceSkippedForTime += 1;
          continue;
        }
        const found = analyzeStagedSource(file.path, file.content);
        if (found === null) {
          report.secretsOnly += 1;
          continue;
        }
        report.sourceChecked += 1;
        const added = addedLineNumbers(file.previous, file.content);
        for (const finding of found) {
          const line = finding.location.line;
          if (line === null || added.has(line)) findings.push({ ...finding, sources: ["code"] });
          else report.preexisting += 1;
        }
      }
    } catch (error) {
      if (context.signal?.aborted === true) throw error;
      const isTimeout =
        (error instanceof GitCommandError && error.kind === "timeout") || now() >= deadline;
      report.failure = isTimeout
        ? {
            kind: "timeout",
            message: `Reading the staged changes did not finish within ${Math.round(budgetMs / 1000)} s; nothing was scanned.`,
          }
        : {
            kind: "error",
            message:
              "The staged changes could not be read from the Git index; nothing was scanned.",
          };
    }
    report.elapsedMs = now() - startedAt;
    settings.onReport?.(report);
    const status: Coverage["status"] =
      report.failure !== null
        ? "not_tested"
        : isStagedReportIncomplete(report)
          ? "partial"
          : "completed";
    return {
      findings: report.failure === null ? findings : [],
      coverage: [
        {
          area: STAGED_COVERAGE_AREA,
          scope: "code",
          status,
          ruleIds: RULE_IDS,
          note: describeStagedReport(report),
        },
      ],
    };
  };
}
