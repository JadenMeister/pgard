import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  PROJECT_CONFIG_FILE,
  applySuppressions,
  parseProjectConfig,
  type Finding,
  type ProjectConfig,
  type ScanResult,
} from "@pgard/findings";
import {
  INCOMPLETE_SKIP_REASONS,
  ScanCancelledError,
  STAGED_COVERAGE_AREA,
  STAGED_SCAN_BUDGET_MS,
  createStagedAnalyzer,
  preflightIsolation,
  readStagedTextFile,
  resolveGitHubAppClientId,
  resolveHookIndexFile,
  resolveHooksLocation,
  type AuthorizationOutcome,
  type ProjectConfigLoad,
  type StagedScanReport,
} from "@pgard/scan-core";
import { err, out, promptContextOf, suspendKeys, type CommandContext } from "../../context.js";
import { EXIT_CODES, type ExitCode } from "../../exit-codes.js";
import { applyStoredBaseline } from "../../flows/baseline.js";
import { promptConfirm, UserCancelledError } from "../../ui/components/prompts.js";
import { formatAuthorization } from "../../ui/formatters/result-view.js";
import { safeText } from "../../ui/formatters/style.js";
import { cliText } from "../../ui/i18n/cli-text.js";
import { installHook, uninstallHook } from "./hook.js";
import { precommitText, type PrecommitText } from "./text.js";

/** The authorization check may take this long (GitHub round trips); then nothing was scanned. */
export const PRECOMMIT_AUTH_TIMEOUT_MS = 15_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 120_000;
/** `PGARD_PRECOMMIT_TIMEOUT_MS`: the authorization time cap, 1000 to 120000. */
export const PRECOMMIT_TIMEOUT_ENV = "PGARD_PRECOMMIT_TIMEOUT_MS";
const MAX_FINDINGS_SHOWN = 20;
const MAX_SKIPPED_SHOWN = 5;

export interface PrecommitRunOptions {
  /** Tests: the authorization time cap. */
  authTimeoutMs?: number;
  /** Tests: the time cap of reading and checking the staged changes. */
  scanBudgetMs?: number;
}

type Policy = "block" | "warn";

interface PrecommitPolicy {
  mode: Policy;
  whenNotScanned: Policy;
  /** The project config is present but invalid: the strict defaults apply. */
  configProblems: string | null;
}

/**
 * What to do with a result. Defaults are strict: `block`, and "not scanned" follows the mode.
 * An invalid config is ignored as a whole (like for a scan), so it cannot weaken the hook.
 */
export function resolvePrecommitPolicy(load: ProjectConfigLoad): PrecommitPolicy {
  if (load.state === "invalid") {
    return { mode: "block", whenNotScanned: "block", configProblems: load.problems.join("; ") };
  }
  const config: ProjectConfig | null = load.state === "loaded" ? load.config : null;
  const mode = config?.precommit?.mode ?? "block";
  return {
    mode,
    whenNotScanned: config?.precommit?.whenNotScanned ?? mode,
    configProblems: null,
  };
}

/** The authorization time cap, and the value of `PGARD_PRECOMMIT_TIMEOUT_MS` when it is unusable. */
function authTimeoutOf(
  env: Readonly<Record<string, string | undefined>>,
  fallback: number | undefined,
): { timeoutMs: number; invalid: string | null } {
  if (fallback !== undefined) return { timeoutMs: fallback, invalid: null };
  const raw = env[PRECOMMIT_TIMEOUT_ENV];
  if (raw === undefined || raw === "")
    return { timeoutMs: PRECOMMIT_AUTH_TIMEOUT_MS, invalid: null };
  const value = /^[0-9]{1,6}$/.test(raw) ? Number(raw) : Number.NaN;
  return value >= MIN_TIMEOUT_MS && value <= MAX_TIMEOUT_MS
    ? { timeoutMs: value, invalid: null }
    : { timeoutMs: PRECOMMIT_AUTH_TIMEOUT_MS, invalid: raw };
}

const STRICT_POLICY: PrecommitPolicy = {
  mode: "block",
  whenNotScanned: "block",
  configProblems: null,
};

/**
 * The policy from the config file that is about to be committed (the staged version). An
 * untracked config is not used; an unreadable or invalid one means the strict default.
 */
async function readStagedPolicy(
  projectRoot: string,
  indexFile: string | undefined,
): Promise<{
  policy: PrecommitPolicy;
  /** The parsed staged config; `null` when there is none or it is not usable. */
  config: ProjectConfig | null;
  /** The working-tree file is not tracked, or differs from the staged copy. */
  workingTree: "untracked" | "differs" | null;
}> {
  const read = await readStagedTextFile(projectRoot, PROJECT_CONFIG_FILE, {
    ...(indexFile === undefined ? {} : { indexFile }),
  });
  const onDisk = await readFile(path.join(projectRoot, PROJECT_CONFIG_FILE), "utf8").catch(
    () => null,
  );
  if (read.state === "absent") {
    return {
      policy: resolvePrecommitPolicy({ state: "absent" }),
      config: null,
      workingTree: onDisk !== null ? "untracked" : null,
    };
  }
  const workingTree = read.state === "ok" && read.text === onDisk ? null : "differs";
  if (read.state === "unreadable") {
    return {
      policy: resolvePrecommitPolicy({
        state: "invalid",
        problems: [`${PROJECT_CONFIG_FILE} ${read.reason}`],
      }),
      config: null,
      workingTree,
    };
  }
  const parsed = parseProjectConfig(read.text);
  return {
    policy: resolvePrecommitPolicy(
      parsed.ok
        ? { state: "loaded", config: parsed.config }
        : { state: "invalid", problems: parsed.problems },
    ),
    config: parsed.ok ? parsed.config : null,
    workingTree,
  };
}

/**
 * Suppressions from the staged config. `runScan` applied the ones in the working-tree file; those
 * marks are dropped and the staged file's suppressions are applied instead, so what is about to be
 * committed decides what is suppressed.
 */
function withStagedSuppressions(result: ScanResult, config: ProjectConfig | null): ScanResult {
  const { suppressions: _workingTree, ...rest } = result;
  const unmarked = result.findings.map(({ suppression: _mark, ...finding }) => finding);
  const applied = applySuppressions(unmarked, config?.suppressions ?? [], new Date());
  return {
    ...rest,
    findings: applied.findings,
    ...(applied.summary === null ? {} : { suppressions: applied.summary }),
  };
}

/** Findings that count: not suppressed, not in the baseline, and not merely informational. */
export function isBlockingFinding(finding: Finding): boolean {
  return (
    finding.suppression === undefined && finding.inBaseline !== true && finding.severity !== "info"
  );
}

type NotScannedKind = "authorization" | "other";

interface Evaluation {
  findings: Finding[];
  /** Part or all of the staged changes was not examined. */
  isNotScanned: boolean;
  kind: NotScannedKind;
}

function location(finding: Finding): string {
  const filePath = finding.location.path ?? finding.location.url ?? "";
  const line = finding.location.line;
  return safeText(line === null ? filePath : `${filePath}:${line}`, 160);
}

function printFindings(
  context: CommandContext,
  t: PrecommitText,
  findings: readonly Finding[],
): void {
  out(context, "");
  out(context, context.style.bold(t.findingsHeading(findings.length)));
  for (const finding of findings.slice(0, MAX_FINDINGS_SHOWN)) {
    out(
      context,
      t.finding(
        finding.severity,
        finding.ruleId,
        location(finding),
        safeText(finding.evidence, 160),
      ),
    );
  }
  if (findings.length > MAX_FINDINGS_SHOWN) {
    out(context, t.moreFindings(findings.length - MAX_FINDINGS_SHOWN));
  }
  for (const ruleId of new Set(findings.map((finding) => finding.ruleId))) {
    const hint = (t.hint as Record<string, string | undefined>)[ruleId];
    if (hint !== undefined) out(context, context.style.dim(`  ${ruleId}: ${hint}`));
  }
}

/** Files skipped by design (binary, symbolic link, submodule), named, so a skip is never hidden. */
function printSkippedByDesign(
  context: CommandContext,
  t: PrecommitText,
  report: StagedScanReport,
): void {
  const parts: string[] = [];
  for (const kind of ["binary", "symlink", "submodule"] as const) {
    const names = report.skipped.filter((item) => item.reason === kind).map((item) => item.path);
    if (names.length === 0) continue;
    const shown = names.slice(0, MAX_SKIPPED_SHOWN).map((name) => safeText(name, 80));
    parts.push(
      t.byDesignKind[kind](
        names.length,
        `${shown.join(", ")}${names.length > shown.length ? ", ..." : ""}`,
      ),
    );
  }
  if (parts.length > 0) out(context, context.style.dim(t.byDesign(parts.join("; "))));
}

function printSkipped(context: CommandContext, t: PrecommitText, report: StagedScanReport): void {
  const skipped = report.skipped.filter((item) => INCOMPLETE_SKIP_REASONS.has(item.reason));
  const reasons = t.skipReason as Record<string, string>;
  for (const item of skipped.slice(0, MAX_SKIPPED_SHOWN)) {
    out(context, t.skippedFile(safeText(item.path, 120), reasons[item.reason] ?? item.reason));
  }
  if (skipped.length > MAX_SKIPPED_SHOWN) {
    out(context, t.moreSkipped(skipped.length - MAX_SKIPPED_SHOWN));
  }
  if (report.sourceSkippedForTime > 0) {
    out(
      context,
      t.skippedFile(`${report.sourceSkippedForTime} file(s)`, reasons.source_time ?? ""),
    );
  }
}

/** The exit code of a finished run, and the decision line that explains it. */
function decide(
  context: CommandContext,
  t: PrecommitText,
  policy: PrecommitPolicy,
  evaluation: Evaluation,
): ExitCode {
  const hasFindings = evaluation.findings.length > 0;
  const blocksOnFindings = hasFindings && policy.mode === "block";
  const blocksOnNotScanned = evaluation.isNotScanned && policy.whenNotScanned === "block";
  out(context, "");
  if (blocksOnFindings || blocksOnNotScanned) {
    if (blocksOnFindings) out(context, context.style.red(t.decisionBlockedFindings));
    if (blocksOnNotScanned && !blocksOnFindings) {
      out(context, context.style.red(t.decisionBlockedNotScanned));
    }
    if (blocksOnFindings) return EXIT_CODES.findings;
    return evaluation.kind === "authorization" ? EXIT_CODES.blocked : EXIT_CODES.partial;
  }
  if (hasFindings) out(context, context.style.yellow(t.decisionWarnFindings));
  if (evaluation.isNotScanned) out(context, context.style.yellow(t.decisionWarnNotScanned));
  if (!hasFindings && !evaluation.isNotScanned) out(context, context.style.green(t.decisionClean));
  return EXIT_CODES.ok;
}

/** Nothing was scanned, said plainly, and the not-scanned policy applied. */
function failNotScanned(
  context: CommandContext,
  t: PrecommitText,
  policy: PrecommitPolicy,
  message: string,
  kind: NotScannedKind,
  details: string[] = [],
): ExitCode {
  err(context, context.errStyle.red(message));
  for (const line of details) err(context, line);
  return decide(context, t, policy, { findings: [], isNotScanned: true, kind });
}

/**
 * `pgard precommit`: checks the staged changes (read from the index, only the lines the commit
 * adds or changes) for secrets and file-local source rule findings.
 *
 * Authorization is the scan's own gate, unchanged: it goes through `runScan`, so all five checks
 * run on every call and nothing is cached or relaxed. Config can only choose how a result ends
 * (`block` or `warn`); it cannot skip a check. When the gate does not allow, or anything goes
 * wrong, the staged changes were not scanned, which is said plainly and handled by
 * `whenNotScanned` (by default the same as `mode`, so a blocking hook blocks).
 */
export async function runPrecommit(
  context: CommandContext,
  options: PrecommitRunOptions = {},
): Promise<ExitCode> {
  const t = precommitText(context.ruleLocale);
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(t.notRepository));
    return EXIT_CODES.blocked;
  }
  // The repository layout check (#370) comes before any further Git process. While the index
  // cannot be read safely, neither can its config: the strict default applies.
  const unsafeLayout = await preflightIsolation(projectRoot);
  if (unsafeLayout !== null && !unsafeLayout.isIsolated) {
    return failNotScanned(
      context,
      t,
      STRICT_POLICY,
      t.repositoryUnsafe(safeText(unsafeLayout.reason, 300)),
      "other",
    );
  }
  const index = await resolveHookIndexFile(
    projectRoot,
    context.io.cwd,
    context.io.env.GIT_INDEX_FILE,
  );
  if (index.state === "unsafe") {
    return failNotScanned(
      context,
      t,
      STRICT_POLICY,
      t.indexUnsafe(safeText(index.reason, 300)),
      "other",
    );
  }
  // Block or warn comes from the config in the index (what is being committed), not from the
  // working tree. Suppressions and `exclude` still come from the working-tree file, as in a scan.
  const staged = await readStagedPolicy(
    projectRoot,
    index.state === "custom" ? index.indexFile : undefined,
  );
  const policy = staged.policy;
  if (policy.configProblems !== null) {
    err(context, context.errStyle.yellow(t.configInvalid(safeText(policy.configProblems, 300))));
  }
  if (staged.workingTree === "untracked") err(context, context.errStyle.yellow(t.configNotStaged));
  if (staged.workingTree === "differs") err(context, context.errStyle.yellow(t.configDiffers));

  const authTimeout = authTimeoutOf(context.io.env, options.authTimeoutMs);
  const authTimeoutMs = authTimeout.timeoutMs;
  if (authTimeout.invalid !== null) {
    err(
      context,
      context.errStyle.yellow(
        t.timeoutInvalid(safeText(authTimeout.invalid, 30), Math.round(authTimeoutMs / 1000)),
      ),
    );
  }
  const budgetMs = options.scanBudgetMs ?? STAGED_SCAN_BUDGET_MS;
  err(
    context,
    context.errStyle.dim(t.checking(Math.round(budgetMs / 1000), Math.round(authTimeoutMs / 1000))),
  );
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), authTimeoutMs);
  const signal = AbortSignal.any([context.signal, timeout.signal]);
  // A hook never starts a device sign-in: a stored sign-in is reused, otherwise the gate blocks.
  const session = context.deps.createSessionProvider({
    env: context.io.env,
    onUserCode: () => undefined,
    onNotice: () => undefined,
    canSignInInteractively: false,
    signal,
  });
  let outcome: AuthorizationOutcome | null = null;
  let report: StagedScanReport | null = null;
  let result: ScanResult;
  suspendKeys(context);
  try {
    result = await context.deps.runScan(
      { projectRoot, scopes: ["code"], webTarget: null },
      {
        authorization: {
          getGitHubSession: session,
          appSlug: resolveGitHubAppClientId(context.io.env).slug,
          signal,
        },
        signal,
        env: context.io.env,
        analyzers: {
          code: createStagedAnalyzer({
            ...(index.state === "custom" ? { indexFile: index.indexFile } : {}),
            config: staged.config,
            budgetMs,
            onReport: (value) => {
              report = value;
            },
          }),
        },
        onAuthorization: (received) => {
          outcome = received;
          // The authorization time cap ends here; the analysis has its own cap and messages.
          clearTimeout(timer);
        },
      },
    );
  } catch (error) {
    if (error instanceof ScanCancelledError) {
      if (context.signal.aborted) throw new UserCancelledError();
      if (timeout.signal.aborted) {
        return failNotScanned(
          context,
          t,
          policy,
          t.authorizationTimeout(Math.round(authTimeoutMs / 1000)),
          "authorization",
          [context.errStyle.dim(t.authorizationHint)],
        );
      }
    }
    // Anything else is an error of the scan itself: nothing was scanned, and it is said so.
    return failNotScanned(context, t, policy, t.scanFailed, "other");
  } finally {
    clearTimeout(timer);
  }

  if (result.overallStatus === "blocked") {
    const lines = [
      formatAuthorization(result.authorization, context.errStyle, cliText(context.ruleLocale)),
    ];
    return failNotScanned(context, t, policy, t.notAuthorized, "authorization", [
      ...lines,
      context.errStyle.dim(t.authorizationHint),
    ]);
  }
  if (result.overallStatus === "failed") {
    return failNotScanned(context, t, policy, t.scanFailed, "other");
  }
  // Baseline and suppressions only decide which findings count; they never change the gate.
  const finished = await applyStoredBaseline(
    context,
    withStagedSuppressions(result, staged.config),
    outcome,
    false,
  );
  const coverage = finished.coverage.find((entry) => entry.area === STAGED_COVERAGE_AREA);
  const scanReport = report as StagedScanReport | null;
  if (coverage === undefined || coverage.status === "not_tested" || scanReport === null) {
    return failNotScanned(
      context,
      t,
      policy,
      scanReport?.failure?.message ?? t.scanFailed,
      "other",
    );
  }
  const counted = finished.findings.filter(isBlockingFinding);
  const suppressed = finished.findings.filter(
    (finding) => finding.suppression !== undefined,
  ).length;
  const inBaseline = finished.findings.filter(
    (finding) => finding.suppression === undefined && finding.inBaseline === true,
  ).length;
  out(context, context.style.dim(t.summary(scanReport.scanned, scanReport.elapsedMs)));
  printSkippedByDesign(context, t, scanReport);
  if (counted.length > 0) printFindings(context, t, counted);
  if (scanReport.preexisting > 0)
    out(context, context.style.dim(t.preexisting(scanReport.preexisting)));
  if (suppressed > 0 || inBaseline > 0) {
    out(context, context.style.dim(t.suppressedAndBaseline(suppressed, inBaseline)));
  }
  const isIncomplete = coverage.status === "partial";
  if (isIncomplete) {
    out(context, "");
    out(context, context.style.yellow(t.incompleteHeading));
    printSkipped(context, t, scanReport);
  }
  return decide(context, t, policy, {
    findings: counted,
    isNotScanned: isIncomplete,
    kind: "other",
  });
}

/** The installed hook file shows up in these messages; paths are display-only. */
function show(file: string): string {
  return safeText(file, 300);
}

/** `pgard precommit install`. */
export async function runPrecommitInstall(context: CommandContext): Promise<ExitCode> {
  const t = precommitText(context.ruleLocale).install;
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(precommitText(context.ruleLocale).notRepository));
    return EXIT_CODES.blocked;
  }
  const location = await resolveHooksLocation(projectRoot);
  if (location.kind === "unsafe") {
    err(context, context.errStyle.red(t.unsafe(safeText(location.reason, 300))));
    return EXIT_CODES.usage;
  }
  if (location.kind === "custom") {
    const hooksPath = safeText(location.hooksPath, 200);
    err(
      context,
      context.errStyle.red(
        location.isInsideRepository ? t.hooksPathInside(hooksPath) : t.hooksPathOutside(hooksPath),
      ),
    );
    return EXIT_CODES.usage;
  }
  const prompts = promptContextOf(
    context,
    "Replace the existing pre-commit hook? The old one is kept next to it.",
  );
  const outcome = await installHook(location.hooksDir, {
    confirmReplace:
      prompts === null
        ? null
        : (backupName) => promptConfirm(prompts, t.existingQuestion(backupName)),
  });
  switch (outcome.kind) {
    case "installed":
    case "replaced":
      out(context, t.installed(show(outcome.file)));
      if (outcome.kind === "replaced") out(context, t.backedUp(show(outcome.backup)));
      out(context, context.style.dim(t.globalHooksPathNote));
      out(context, context.style.dim(t.mergeNote));
      out(context, context.style.dim(t.nextStep));
      return EXIT_CODES.ok;
    case "already":
      out(context, t.alreadyInstalled(show(outcome.file)));
      return EXIT_CODES.ok;
    case "needs_terminal":
      err(context, context.errStyle.red(t.existingNeedsTerminal));
      return EXIT_CODES.usage;
    case "declined":
      out(context, t.existingDeclined);
      return EXIT_CODES.ok;
    case "failed":
      err(context, context.errStyle.red(t.failed));
      return EXIT_CODES.partial;
  }
}

/** `pgard precommit uninstall`: removes the hook only when PGARD wrote it. */
export async function runPrecommitUninstall(context: CommandContext): Promise<ExitCode> {
  const text = precommitText(context.ruleLocale);
  const t = text.uninstall;
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(text.notRepository));
    return EXIT_CODES.blocked;
  }
  const location = await resolveHooksLocation(projectRoot);
  if (location.kind === "unsafe") {
    err(context, context.errStyle.red(text.install.unsafe(safeText(location.reason, 300))));
    return EXIT_CODES.usage;
  }
  if (location.kind === "custom") {
    // PGARD never wrote there, so it never removes from there.
    const hooksPath = safeText(location.hooksPath, 200);
    err(
      context,
      context.errStyle.red(
        location.isInsideRepository
          ? text.install.hooksPathInside(hooksPath)
          : text.install.hooksPathOutside(hooksPath),
      ),
    );
    return EXIT_CODES.usage;
  }
  const outcome = await uninstallHook(location.hooksDir);
  switch (outcome.kind) {
    case "removed":
      out(context, t.removed(show(outcome.file)));
      if (outcome.backup !== null) out(context, t.backupFound(show(outcome.backup)));
      return EXIT_CODES.ok;
    case "absent":
      out(context, t.notInstalled);
      if (outcome.backup !== null) out(context, t.backupFound(show(outcome.backup)));
      return EXIT_CODES.ok;
    case "not_ours":
      out(context, t.notOurs(show(outcome.file)));
      return EXIT_CODES.ok;
    case "failed":
      err(context, context.errStyle.red(t.failed));
      return EXIT_CODES.partial;
  }
}

/** `pgard precommit snippet`: the lines for hook managers; writes nothing. */
export function runPrecommitSnippet(context: CommandContext): ExitCode {
  const t = precommitText(context.ruleLocale).snippet;
  out(context, t.heading);
  out(context, "");
  out(context, t.preCommitFramework);
  out(
    context,
    [
      "  repos:",
      "    - repo: local",
      "      hooks:",
      "        - id: pgard-precommit",
      "          name: pgard precommit",
      "          entry: pgard precommit",
      "          language: system",
      "          pass_filenames: false",
      "          always_run: true",
    ].join("\n"),
  );
  out(context, "");
  out(context, t.husky);
  out(context, "  pgard precommit");
  out(context, "");
  out(context, t.plain);
  out(context, `  #!/bin/sh\n  exec pgard precommit`);
  out(context, "");
  out(context, t.merge);
  return EXIT_CODES.ok;
}
