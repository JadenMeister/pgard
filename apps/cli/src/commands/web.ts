import { loadSearchScope, type LoadedScope, type RootRejection } from "@pgard/result-store";
import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { EXIT_CODES, toKnownExitCode, type ExitCode } from "../exit-codes.js";
import { isStoreDisabled } from "../flows/baseline.js";
import { promptConfirm } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";

const WEB_HELP = `The picker searches only the folders listed here. The browser sends only a folder
name; you confirm the real path and the GitHub remote there before anything is checked.
Add or remove search folders with pgard web scope add <folder> or remove <folder>.`;

export const WINDOWS_PICKER_MESSAGE =
  "The project picker is not available on Windows yet. Run `pgard dashboard` in the project folder instead.";

/** Fixed English reasons a search folder is not used (shown in the terminal, the trusted channel). */
export const ROOT_REJECTION_TEXT: Record<RootRejection, string> = {
  not_absolute: "is not an absolute path",
  missing: "does not exist",
  not_a_directory: "is not a folder",
  symlink: "is a symbolic link",
  too_shallow: "is too high up (it must be at least two levels deep, so not / or /Users)",
  not_owned_by_you: "belongs to another user",
  group_or_world_writable:
    "can be changed by other users (remove their write access with chmod go-w)",
  unreadable: "could not be read",
  unsupported_platform: "is not supported on this platform",
};

export function homeDirOf(context: CommandContext): string {
  return context.io.env.HOME ?? context.io.env.USERPROFILE ?? "";
}

export async function loadScopeFor(
  context: CommandContext,
  isStoreOff: boolean,
): Promise<LoadedScope> {
  const storage = isStoreOff ? null : context.deps.openWebStorage(context.io.env);
  return loadSearchScope({
    storage,
    uid: process.getuid?.(),
    homeDir: homeDirOf(context),
    platform: context.deps.platform,
  });
}

/** Prints the roots (paths are shown here on purpose: this is the trusted channel). */
export function printScope(context: CommandContext, scope: LoadedScope): void {
  out(
    context,
    scope.source === "stored"
      ? "Search folders (saved in settings.json):"
      : "Search folders (the default development folders that exist):",
  );
  for (const root of scope.roots) out(context, `  ${safeText(root.path, 500)}`);
  for (const dropped of scope.dropped) {
    err(
      context,
      context.errStyle.yellow(
        `  Skipped ${safeText(dropped.path, 500)}: it ${ROOT_REJECTION_TEXT[dropped.reason]}.`,
      ),
    );
  }
  if (scope.settingsIgnored) {
    err(
      context,
      context.errStyle.yellow(
        "  The saved search folders could not be read (damaged, unsafe or from a newer PGARD) and are ignored. Delete web/settings.json in the PGARD data folder to start over.",
      ),
    );
  }
}

/**
 * `pgard web`: confirm the search folders in the terminal, then start the separately installed
 * local-web launcher in picker mode with this Node binary (no shell, and no path on the command
 * line). The project itself is chosen and confirmed in the browser.
 */
export async function runWeb(
  context: CommandContext,
  noBrowser: boolean,
  noStore: boolean,
): Promise<ExitCode> {
  if (context.deps.platform === "win32") {
    err(context, context.errStyle.red(WINDOWS_PICKER_MESSAGE));
    return EXIT_CODES.usage;
  }
  const prompts = promptContextOf(context, WEB_HELP);
  if (prompts === null) {
    err(context, "pgard web needs an interactive terminal to confirm the search folders.");
    return EXIT_CODES.usage;
  }
  const entry = context.deps.resolveDashboardEntry();
  if (entry === null) {
    err(
      context,
      context.errStyle.red("The local web dashboard is not installed with this pgard build."),
    );
    return EXIT_CODES.internal;
  }
  const isStoreOff = isStoreDisabled(context, noStore);
  const scope = await loadScopeFor(context, isStoreOff);
  printScope(context, scope);
  if (scope.roots.length === 0) {
    err(
      context,
      context.errStyle.red("No usable search folder. Add one first: pgard web scope add <folder>"),
    );
    return EXIT_CODES.usage;
  }
  const isConfirmed = await promptConfirm(prompts, "Search these folders for projects?");
  if (!isConfirmed) return EXIT_CODES.cancelled;
  // First run: the confirmed default folders are saved (not with --no-store: the question is
  // then asked again at the next launch).
  if (scope.source === "default" && !isStoreOff) {
    const saved = await context.deps
      .openWebStorage(context.io.env)
      ?.writeSettings(scope.roots.map((root) => root.path));
    if (saved !== undefined && !saved.ok) {
      err(
        context,
        context.errStyle.yellow(
          "The search folders could not be saved; you will be asked again next time.",
        ),
      );
    }
  }
  const args = ["--picker"];
  if (noBrowser) args.push("--no-browser");
  if (isStoreOff) args.push("--no-store");
  context.keys?.close();
  // The dashboard process handles Ctrl+C itself; stop our scan-cancel prompt from printing.
  context.releaseInterrupts();
  return toKnownExitCode(await context.deps.startDashboardProcess(entry, args));
}
