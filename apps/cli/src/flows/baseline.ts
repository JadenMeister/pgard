import {
  applyBaseline,
  SEVERITIES,
  baselineSnapshot,
  summarizeBySeverity,
  type ScanResult,
} from "@pgard/findings";
import type { ResultStore } from "@pgard/result-store";
import { isAuthorizationAllowed, type AuthorizationOutcome } from "@pgard/scan-core";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { err, out, type CommandContext } from "../context.js";
import { safeText } from "../ui/formatters/style.js";
import { formatScanTime } from "./scan-diff-summary.js";
import { NO_STORE_ENV } from "./store-result.js";

/** `--no-store` or `PGARD_NO_STORE=1`: nothing is read from or written to the result store. */
export function isStoreDisabled(context: CommandContext, noStoreFlag: boolean): boolean {
  return noStoreFlag || context.io.env[NO_STORE_ENV] === "1";
}

function isNewerMinor(version: string, current: string): boolean {
  const [major = 0, minor = 0] = version.split(".").map(Number);
  const [currentMajor = 0, currentMinor = 0] = current.split(".").map(Number);
  return major > currentMajor || (major === currentMajor && minor > currentMinor);
}

/**
 * Applies the repository's baseline (if any) to a finished scan: findings that match it get
 * `inBaseline`, and `baseline` carries the counts. Never changes the status or the exit code, never
 * removes a finding, and never touches authorization (it runs after the gate, on the outcome the
 * gate produced in this very run).
 *
 * Skipped silently only when there is nothing to apply: storing is off (`--no-store`,
 * `PGARD_NO_STORE=1`), the scan was blocked or failed, or the repository has no baseline. A
 * baseline that exists but cannot be used (unreadable, written by a newer PGARD) is a warning on
 * stderr and the scan is shown without it, so everything is listed as usual.
 */
export async function applyStoredBaseline(
  context: CommandContext,
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  noStoreFlag: boolean,
): Promise<ScanResult> {
  if (isStoreDisabled(context, noStoreFlag)) return result;
  if (outcome === null || !isAuthorizationAllowed(outcome)) return result;
  if (result.overallStatus === "blocked" || result.overallStatus === "failed") return result;
  const repositoryId = outcome.repositoryId;
  if (typeof repositoryId !== "number") return result;
  try {
    const store = context.deps.openResultStore(context.io.env);
    if (store === null) return result;
    const loaded = await store.getBaseline(repositoryId);
    if (!loaded.ok) {
      err(
        context,
        context.errStyle.yellow(
          `The baseline could not be read and was not applied: ${safeText(loaded.error.message, 200)} Fix it, or run pgard baseline clear.`,
        ),
      );
      return result;
    }
    const baseline = loaded.baseline;
    if (baseline === null) return result;
    if (isNewerMinor(baseline.sourceVersion, result.schemaVersion)) {
      err(
        context,
        context.errStyle.yellow(
          `The baseline uses schema version ${safeText(baseline.sourceVersion, 12)}, newer than this PGARD understands, and was not applied.`,
        ),
      );
      return result;
    }
    return applyBaseline(result, baseline.result, baseline.setAt).result;
  } catch {
    err(context, context.errStyle.yellow("The baseline could not be applied."));
    return result;
  }
}

export function describeFindings(result: ScanResult): string {
  const counts = summarizeBySeverity(result.findings);
  const parts = SEVERITIES.filter((severity) => counts[severity] > 0).map(
    (severity) => `${counts[severity]} ${severity}`,
  );
  return `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}${parts.length > 0 ? ` (${parts.join(", ")})` : ""}`;
}

/**
 * Stores `result` as the baseline of the repository. Used by `pgard baseline set` (newest stored
 * scan) and `--from-current` (the scan that just ran). A partial scan is accepted but says what
 * that means: later findings in the parts it did not cover read as new.
 */
export async function storeBaseline(
  context: CommandContext,
  store: ResultStore,
  result: ScanResult,
  repositoryId: number,
  projectRoot: string,
  savedAt: Date | null,
): Promise<ExitCode> {
  const home = context.io.env.HOME ?? context.io.env.USERPROFILE ?? "";
  const forbidSubstrings = home.length > 3 ? [projectRoot, home] : [projectRoot];
  const saved = await store.setBaseline(baselineSnapshot(result), {
    repositoryId,
    forbidSubstrings,
  });
  if (!saved.ok) {
    err(
      context,
      context.errStyle.red(`The baseline was not saved: ${safeText(saved.error.message, 200)}`),
    );
    return EXIT_CODES.partial;
  }
  const when = savedAt === null ? "this scan" : `the scan of ${formatScanTime(savedAt)}`;
  const snapshot = baselineSnapshot(result);
  const left = result.findings.length - snapshot.findings.length;
  out(
    context,
    `Baseline set from ${when}: ${describeFindings(snapshot)}. Later scans list the findings that match it under "In baseline" and highlight the new ones. Nothing is hidden.`,
  );
  if (left > 0) {
    out(
      context,
      context.style.yellow(
        `! ${left} finding${left === 1 ? " is" : "s are"} suppressed by pgard.config.json and ${left === 1 ? "was" : "were"} left out of the baseline: ${left === 1 ? "it" : "they"} will read as new when the suppression is removed or expires.`,
      ),
    );
  }
  if (result.overallStatus !== "completed") {
    out(
      context,
      context.style.yellow(
        `! That scan was ${result.overallStatus}: findings in the areas it did not cover will read as new.`,
      ),
    );
  }
  out(context, context.style.dim(`Stored in ${store.dir}. Remove it with pgard baseline clear.`));
  return EXIT_CODES.ok;
}
