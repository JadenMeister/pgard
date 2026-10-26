import { isAuthorizationAllowed } from "@pgard/scan-core";
import { err, out, suspendKeys, throwIfCancelled, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { createSessionProvider } from "../flows/authenticate.js";
import { describeFindings, isStoreDisabled, storeBaseline } from "../flows/baseline.js";
import { authorizationDepsFor } from "../flows/guided-install.js";
import { findPreviousScan, formatScanTime } from "../flows/scan-diff-summary.js";
import { NO_STORE_ENV } from "../flows/store-result.js";
import type { BaselineAction } from "../options.js";
import { formatAuthorization } from "../ui/formatters/result-view.js";
import { safeText } from "../ui/formatters/style.js";
import { NOT_A_REPOSITORY_MESSAGE } from "./project/verify.js";
import { runScanCommand } from "./scan/index.js";

export const BASELINE_STORE_OFF_MESSAGE = `Baselines live in the local result store, which is turned off by ${NO_STORE_ENV}=1. Unset it to use pgard baseline.`;

/** `pgard baseline set|show|clear`. */
export async function runBaseline(
  context: CommandContext,
  action: BaselineAction,
  fromCurrent: boolean,
): Promise<ExitCode> {
  if (isStoreDisabled(context, false)) {
    err(context, context.errStyle.red(BASELINE_STORE_OFF_MESSAGE));
    return EXIT_CODES.usage;
  }
  if (action === "set" && fromCurrent) {
    return runScanCommand(context, {
      variant: "default",
      port: null,
      report: null,
      format: "text",
      allFindings: false,
      setBaseline: true,
    });
  }
  const store = context.deps.openResultStore(context.io.env);
  if (store === null) {
    err(context, context.errStyle.red("No app-data directory could be determined."));
    return EXIT_CODES.internal;
  }
  const projectRoot = await context.deps.findGitRoot(context.io.cwd);
  if (projectRoot === null) {
    err(context, context.errStyle.red(NOT_A_REPOSITORY_MESSAGE));
    return EXIT_CODES.blocked;
  }
  // The store is keyed by GitHub's repository id, so the gate runs first, like for a scan.
  suspendKeys(context);
  const authorization = authorizationDepsFor(context, createSessionProvider(context));
  const outcome = await context.deps.verifyProject(projectRoot, authorization);
  throwIfCancelled(context);
  if (!isAuthorizationAllowed(outcome) || typeof outcome.repositoryId !== "number") {
    out(context, formatAuthorization(outcome.summary, context.style));
    err(
      context,
      context.errStyle.red(
        "The baseline is kept per verified repository, and this one is not verified. Run pgard project verify.",
      ),
    );
    return EXIT_CODES.blocked;
  }
  const repositoryId = outcome.repositoryId;
  const name = safeText(outcome.repo ?? "this repository", 120);

  if (action === "clear") {
    const removed = await store.clearBaseline(repositoryId);
    out(context, removed ? `Baseline of ${name} cleared.` : `There was no baseline for ${name}.`);
    return EXIT_CODES.ok;
  }
  if (action === "show") {
    const loaded = await store.getBaseline(repositoryId);
    if (!loaded.ok) {
      err(
        context,
        context.errStyle.red(
          `The baseline could not be read: ${safeText(loaded.error.message, 200)} Run pgard baseline clear, then set it again.`,
        ),
      );
      return EXIT_CODES.partial;
    }
    if (loaded.baseline === null) {
      out(
        context,
        `No baseline for ${name}. Set one with pgard baseline set (newest stored scan) or pgard baseline set --from-current.`,
      );
      return EXIT_CODES.ok;
    }
    const { baseline } = loaded;
    out(context, context.style.bold(`Baseline of ${name}`));
    out(context, `  Set:      ${formatScanTime(baseline.setAt)} (local time)`);
    out(
      context,
      `  Scan:     ${safeText(baseline.result.scanId, 40)} at ${safeText((baseline.result.target.revision ?? "unknown").slice(0, 12), 20)}, ${baseline.result.overallStatus}, scopes ${baseline.result.requestedScopes.join(", ")}`,
    );
    out(context, `  Findings: ${describeFindings(baseline.result)}`);
    out(
      context,
      context.style.dim(
        'Scans list matching findings under "In baseline". pgard scan --no-store (or PGARD_NO_STORE=1) does not apply it.',
      ),
    );
    return EXIT_CODES.ok;
  }
  // set: the newest stored scan of this repository.
  const found = await findPreviousScan(store, repositoryId, "");
  for (const warning of found.warnings) {
    err(context, context.errStyle.yellow(safeText(warning, 200)));
  }
  if (found.scan === null) {
    err(
      context,
      context.errStyle.red(
        `No stored scan of ${name}. Run pgard scan first, or use pgard baseline set --from-current.`,
      ),
    );
    return EXIT_CODES.usage;
  }
  return storeBaseline(
    context,
    store,
    found.scan.result,
    repositoryId,
    projectRoot,
    found.scan.savedAt,
  );
}
