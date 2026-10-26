import {
  compareScans,
  type IncrementalState,
  type RuleLocale,
  type ScanResult,
} from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { isAuthorizationAllowed } from "@pgard/scan-core";
import { err, out, type CommandContext } from "../context.js";
import type { ScanDiff } from "../ui/formatters/result-summary.js";
import { safeText } from "../ui/formatters/style.js";
import { cliText } from "../ui/i18n/cli-text.js";
import {
  findPreviousScan,
  formatWarnings,
  summarizeSinceLastScan,
  type PreviousScan,
} from "./scan-diff-summary.js";

/** Environment opt-out: `PGARD_NO_STORE=1` keeps scans from being stored (same as `--no-store`). */
export const NO_STORE_ENV = "PGARD_NO_STORE";

export function firstRunNotice(
  dir: string,
  platform: NodeJS.Platform = process.platform,
  locale: RuleLocale = "en",
): string {
  return cliText(locale).notices.firstRun(dir, platform === "win32");
}

/** Whether this run's result is stored at all (the same rules for storing and for comparing). */
function storeFor(
  context: CommandContext,
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  noStoreFlag: boolean,
) {
  if (noStoreFlag || context.io.env[NO_STORE_ENV] === "1") return null;
  const store = context.deps.openResultStore(context.io.env);
  if (store === null) return null;
  if (outcome === null || !isAuthorizationAllowed(outcome)) return null;
  if (result.overallStatus === "blocked" || result.overallStatus === "failed") return null;
  const repositoryId = outcome.repositoryId;
  if (typeof repositoryId !== "number") return null;
  return { store, repositoryId };
}

/**
 * The newest earlier stored scan of this repository, read before the result is shown so the
 * summary can say what changed, and before it is saved so "previous" is never this scan. `null`
 * when nothing is stored for this run (opt-out, no store, not authorized) or the read failed.
 */
export async function loadPreviousScan(
  context: CommandContext,
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  noStoreFlag: boolean,
): Promise<PreviousScan | null> {
  const target = storeFor(context, result, outcome, noStoreFlag);
  if (target === null) return null;
  return findPreviousScan(target.store, target.repositoryId, result.scanId).catch(() => null);
}

/** The comparison for the summary block; `null` without an earlier scan or when it fails. */
export function scanDiffOf(result: ScanResult, previous: PreviousScan | null): ScanDiff | null {
  if (previous === null || previous.scan === null) return null;
  try {
    return {
      comparison: compareScans(previous.scan.result, result),
      previousSavedAt: previous.scan.savedAt,
    };
  } catch {
    return null;
  }
}

/**
 * Stores a finished scan locally unless the user opted out. Runs once, after the scan, and never
 * affects the scan or its exit code: a store problem is a warning on stderr.
 *
 * Only a scan the gate allowed in this very run is stored, under GitHub's repository id from
 * that run's authorization. Nothing here is read back to authorize anything.
 *
 * After a successful save, the newest earlier stored scan of the same repository (if any) is
 * compared and one summary line is printed: on stdout in text mode, on stderr with
 * `--format json` (stdout carries only the result document). The first scan prints nothing. The
 * previous result is read through `readScanResult` with a size cap, only compared, never trusted
 * for authorization; a comparison problem is silent apart from a warning on stderr.
 */
export async function storeScanResult(
  context: CommandContext,
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  projectRoot: string,
  noStoreFlag: boolean,
  isJson = false,
  /** Already read by `loadPreviousScan` (text mode shows the comparison in the summary). */
  preloaded?: PreviousScan | null,
  /** What the next scan can reuse (see `createIncrementalHandle`); stored with the result. */
  incrementalState?: IncrementalState | null,
): Promise<void> {
  const target = storeFor(context, result, outcome, noStoreFlag);
  if (target === null) return;
  const { store, repositoryId } = target;
  const t = cliText(context.ruleLocale);
  try {
    // The home directory must not appear either (redaction replaces the project root only).
    const home = context.io.env.HOME ?? context.io.env.USERPROFILE ?? "";
    const forbidSubstrings = home.length > 3 ? [projectRoot, home] : [projectRoot];
    // Read the previous scan before saving, so "previous" can never be this scan.
    const previous =
      preloaded === undefined
        ? await findPreviousScan(store, repositoryId, result.scanId).catch(() => null)
        : preloaded;
    const saved = await store.save(result, { repositoryId, forbidSubstrings, incrementalState });
    if (saved.ok) {
      // Only after a successful save, and on stderr, so stdout (including any JSON) is untouched.
      if (await store.claimFirstRunNotice()) {
        err(context, firstRunNotice(store.dir, process.platform, context.ruleLocale));
      }
      if (previous !== null) {
        for (const line of formatWarnings(previous.warnings, t)) {
          err(context, context.errStyle.yellow(line));
        }
        if (previous.scan !== null) {
          try {
            const line = summarizeSinceLastScan(result, previous.scan, t);
            if (isJson) err(context, context.errStyle.dim(line));
            else out(context, line);
          } catch {
            err(context, context.errStyle.yellow(t.notices.notComparable));
          }
        }
      }
    } else {
      err(
        context,
        context.errStyle.yellow(t.notices.notStored(safeText(saved.error.message, 200))),
      );
    }
  } catch {
    err(context, context.errStyle.yellow(t.notices.notStoredShort));
  }
}
