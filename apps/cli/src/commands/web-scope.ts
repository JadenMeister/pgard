import path from "node:path";
import { MAX_SEARCH_ROOTS, nodeScopeFs, validateSearchRoot } from "@pgard/result-store";
import { err, out, promptContextOf, type CommandContext } from "../context.js";
import { EXIT_CODES, type ExitCode } from "../exit-codes.js";
import { isStoreDisabled } from "../flows/baseline.js";
import { promptConfirm } from "../ui/components/prompts.js";
import { safeText } from "../ui/formatters/style.js";
import type { WebScopeAction } from "../options.js";
import {
  homeDirOf,
  loadScopeFor,
  printScope,
  ROOT_REJECTION_TEXT,
  WINDOWS_PICKER_MESSAGE,
} from "./web.js";

const SCOPE_HELP = `Search folders are changed here, in the terminal, never in the browser.
Each one must be yours, not writable by group or others, and at least two levels deep.`;

const HOME_WARNING =
  "This is your whole home folder. On macOS, searching it triggers permission prompts for protected folders and can make iCloud download files that are only stored online. Prefer a folder such as ~/code.";

/** `~` and `~/x` are expanded here (a quoted `~` reaches us unexpanded); relative paths use the cwd. */
function expandFolder(context: CommandContext, raw: string): string {
  const home = homeDirOf(context);
  if (home !== "" && (raw === "~" || raw.startsWith("~/")))
    return path.posix.join(home, raw.slice(1));
  return path.posix.resolve(context.io.cwd, raw);
}

/** `pgard web scope list | add <folder> | remove <folder>`. */
export async function runWebScope(
  context: CommandContext,
  action: WebScopeAction,
  folder: string | null,
): Promise<ExitCode> {
  if (context.deps.platform === "win32") {
    err(context, context.errStyle.red(WINDOWS_PICKER_MESSAGE));
    return EXIT_CODES.usage;
  }
  const storage = context.deps.openWebStorage(context.io.env);
  if (storage === null) {
    err(context, context.errStyle.red("No app-data directory could be determined."));
    return EXIT_CODES.internal;
  }
  // Under --no-store / PGARD_NO_STORE=1 nothing is read from or written to the picker's files:
  // the folders are the defaults, and add and remove (which write) are refused.
  const isStoreOff = isStoreDisabled(context, false);
  if (isStoreOff && action !== "list") {
    err(
      context,
      context.errStyle.red(
        "PGARD_NO_STORE=1 is set, so nothing is saved: the search folders cannot be changed. Unset it and run the command again.",
      ),
    );
    return EXIT_CODES.usage;
  }
  const scope = await loadScopeFor(context, isStoreOff);
  if (action === "list") {
    printScope(context, scope);
    if (scope.roots.length === 0) {
      out(context, "No usable search folders. Add one with: pgard web scope add <folder>");
    }
    return EXIT_CODES.ok;
  }
  if (scope.settingsIgnored) {
    printScope(context, scope);
    return EXIT_CODES.blocked;
  }
  const target = expandFolder(context, folder ?? "");
  // The saved list as it is (also entries that are no longer usable, so they can be removed); the
  // default folders that exist when nothing was saved yet.
  const saved = await storage.readSettings();
  const current = saved.status === "ok" ? saved.value.roots : scope.roots.map((root) => root.path);

  if (action === "remove") {
    const checked = await validateSearchRoot(
      target,
      nodeScopeFs,
      process.getuid?.(),
      context.deps.platform,
    );
    // A folder that no longer exists or is no longer safe can still be removed by its saved path.
    const wanted = checked.ok ? checked.path : target;
    if (!current.includes(wanted) && !current.includes(target)) {
      err(context, context.errStyle.red(`${safeText(target, 500)} is not a search folder.`));
      return EXIT_CODES.usage;
    }
    const written = await storage.writeSettings(
      current.filter((entry) => entry !== wanted && entry !== target),
    );
    if (!written.ok) return reportWriteFailure(context);
    out(context, `Removed ${safeText(wanted, 500)} from the search folders.`);
    return EXIT_CODES.ok;
  }

  const checked = await validateSearchRoot(
    target,
    nodeScopeFs,
    process.getuid?.(),
    context.deps.platform,
  );
  if (!checked.ok) {
    err(
      context,
      context.errStyle.red(
        `${safeText(target, 500)} cannot be a search folder: it ${ROOT_REJECTION_TEXT[checked.reason]}.`,
      ),
    );
    return EXIT_CODES.usage;
  }
  const prompts = promptContextOf(context, SCOPE_HELP);
  if (prompts === null) {
    err(context, "pgard web scope add needs an interactive terminal to confirm the folder.");
    return EXIT_CODES.usage;
  }
  out(context, `Real path: ${safeText(checked.path, 500)}`);
  if (!current.includes(checked.path) && current.length >= MAX_SEARCH_ROOTS) {
    err(
      context,
      context.errStyle.red(
        `At most ${MAX_SEARCH_ROOTS} search folders can be saved. Remove one first: pgard web scope remove <folder>`,
      ),
    );
    return EXIT_CODES.usage;
  }
  if (current.includes(checked.path)) {
    out(context, "It is already a search folder.");
    return EXIT_CODES.ok;
  }
  const home = homeDirOf(context);
  if (home !== "" && checked.path === home) {
    out(context, context.errStyle.yellow(HOME_WARNING));
  }
  if (!(await promptConfirm(prompts, "Add it to the folders pgard web searches?"))) {
    return EXIT_CODES.cancelled;
  }
  const written = await storage.writeSettings([...current, checked.path]);
  if (!written.ok) return reportWriteFailure(context);
  out(context, `Added ${safeText(checked.path, 500)} to the search folders.`);
  return EXIT_CODES.ok;
}

function reportWriteFailure(context: CommandContext): ExitCode {
  err(
    context,
    context.errStyle.red(
      "The search folders could not be saved (the settings file is unreadable, from a newer PGARD, or its folder is unsafe). Delete web/settings.json in the PGARD data folder and try again.",
    ),
  );
  return EXIT_CODES.internal;
}
