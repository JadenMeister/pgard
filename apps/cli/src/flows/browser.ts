import { isOpenableGitHubUrl } from "@pgard/scan-core";
import { waitForEnter } from "../adapters/terminal.js";
import { err, type CommandContext } from "../context.js";

/**
 * Opens a GitHub page in the system browser when `context.canOpenBrowser` (stdout is a TTY and
 * `--no-browser` was not given). Callers always print the URL as well; only
 * `https://github.com/` URLs are opened. Failing to open is not an error.
 */
export async function openInBrowser(context: CommandContext, url: string): Promise<boolean> {
  if (!context.canOpenBrowser || !isOpenableGitHubUrl(url)) return false;
  let isOpened = false;
  try {
    isOpened = await context.deps.openBrowser(url);
  } catch {
    isOpened = false;
  }
  if (!isOpened) {
    err(context, context.errStyle.dim("Could not open a browser; open the link above yourself."));
  }
  return isOpened;
}

export const OPEN_PROMPT = "Press Enter to open github.com in your browser...";

const activeOffers = new WeakMap<CommandContext, Set<() => void>>();

/**
 * In a terminal, prints the prompt and opens `url` only after the user presses Enter (through
 * `openInBrowser`, so the github.com check still applies). Never blocks: the caller keeps
 * working (polling) and calls the returned `stop` when the page is no longer needed (sign-in or
 * installation done, cancelled, failed); the prompt is then abandoned and stdin released. Other
 * keys are ignored. Does nothing (returns a no-op) without `canOpenBrowser`, for a URL that is
 * not an openable github.com page, or when stdin is not a terminal or has already ended
 * (nobody can press Enter). The caller prints the URL either way.
 */
export function offerBrowserOpen(context: CommandContext, url: string): () => void {
  const { stdin } = context.io;
  if (
    !context.canOpenBrowser ||
    !isOpenableGitHubUrl(url) ||
    stdin.isTTY !== true ||
    stdin.readableEnded === true
  ) {
    return () => undefined;
  }
  // Backstop (callers already suspend before long work): leave raw mode if a prompt left it on,
  // so Ctrl+C stays a SIGINT while we wait.
  context.keys?.suspend();
  err(context, context.errStyle.dim(OPEN_PROMPT));
  let stopWaiting = (): void => undefined;
  const offers = activeOffers.get(context) ?? new Set<() => void>();
  activeOffers.set(context, offers);
  const stop = (): void => {
    offers.delete(stop);
    stopWaiting();
  };
  offers.add(stop);
  stopWaiting = waitForEnter(
    context.io.stdin,
    () => {
      offers.delete(stop);
      void openInBrowser(context, url);
    },
    context.deps.now,
  );
  return stop;
}

/** Abandons every Enter prompt still shown for this command. */
export function stopBrowserOffers(context: CommandContext): void {
  for (const stop of [...(activeOffers.get(context) ?? [])]) stop();
}
