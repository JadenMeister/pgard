import { isOpenableGitHubUrl } from "@pgard/scan-core";
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
