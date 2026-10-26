import type { ScanResult } from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { isAuthorizationAllowed } from "@pgard/scan-core";
import { err, type CommandContext } from "../context.js";
import { safeText } from "../ui/formatters/style.js";

/** Environment opt-out: `PGARD_NO_STORE=1` keeps scans from being stored (same as `--no-store`). */
export const NO_STORE_ENV = "PGARD_NO_STORE";

export function firstRunNotice(dir: string, platform: NodeJS.Platform = process.platform): string {
  const access =
    platform === "win32"
      ? "nothing is uploaded; access follows your Windows profile folder"
      : "readable only by you; nothing is uploaded";
  return [
    "PGARD now keeps your scan results on this computer, so later scans can be compared.",
    `  Where: ${dir} (${access})`,
    "  What: the redacted result only, last 20 scans per repository for 90 days.",
    "  Stop storing: pass --no-store, or set PGARD_NO_STORE=1.",
    "  Delete everything: pgard history clear --all",
  ].join("\n");
}

/**
 * Stores a finished scan locally unless the user opted out. Runs once, after the scan, and never
 * affects the scan or its exit code: a store problem is a warning on stderr.
 *
 * Only a scan the gate allowed in this very run is stored, under GitHub's repository id from
 * that run's authorization. Nothing here is read back to authorize anything.
 */
export async function storeScanResult(
  context: CommandContext,
  result: ScanResult,
  outcome: AuthorizationOutcome | null,
  projectRoot: string,
  noStoreFlag: boolean,
): Promise<void> {
  if (noStoreFlag || context.io.env[NO_STORE_ENV] === "1") return;
  const store = context.deps.openResultStore(context.io.env);
  if (store === null) return;
  if (outcome === null || !isAuthorizationAllowed(outcome)) return;
  if (result.overallStatus === "blocked" || result.overallStatus === "failed") return;
  const repositoryId = outcome.repositoryId;
  if (typeof repositoryId !== "number") return;
  try {
    // The home directory must not appear either (redaction replaces the project root only).
    const home = context.io.env.HOME ?? context.io.env.USERPROFILE ?? "";
    const forbidSubstrings = home.length > 3 ? [projectRoot, home] : [projectRoot];
    const saved = await store.save(result, { repositoryId, forbidSubstrings });
    if (saved.ok) {
      // Only after a successful save, and on stderr, so stdout (including any JSON) is untouched.
      if (await store.claimFirstRunNotice()) err(context, firstRunNotice(store.dir));
    } else {
      err(
        context,
        context.errStyle.yellow(
          `The scan result was not stored: ${safeText(saved.error.message, 200)}`,
        ),
      );
    }
  } catch {
    err(context, context.errStyle.yellow("The scan result was not stored."));
  }
}
