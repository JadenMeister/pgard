import { spawn } from "node:child_process";
import { isOpenableGitHubUrl } from "./app-install.js";

export interface OpenerCommand {
  command: string;
  args: string[];
}

/**
 * The platform's URL opener with a fixed argument vector (never a shell string):
 * macOS `open <url>`, Windows `explorer.exe <url>`, everything else `xdg-open <url>`.
 *
 * Windows uses `explorer.exe` rather than `cmd /c start`, because cmd would parse `&` in the
 * query string as a command separator. `null` when the URL is not an `https://github.com/` URL.
 */
export function openerCommandFor(platform: NodeJS.Platform, url: string): OpenerCommand | null {
  if (!isOpenableGitHubUrl(url)) return null;
  switch (platform) {
    case "darwin":
      return { command: "open", args: [url] };
    case "win32":
      return { command: "explorer.exe", args: [url] };
    default:
      return { command: "xdg-open", args: [url] };
  }
}

export type SpawnOpener = (command: string, args: readonly string[]) => Promise<boolean>;

/** Starts the opener detached, without a shell, ignoring its output. Never rejects. */
export const spawnOpener: SpawnOpener = (command, args) =>
  new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, [...args], { stdio: "ignore", detached: true, shell: false });
    } catch {
      resolve(false);
      return;
    }
    child.once("error", () => resolve(false));
    child.once("spawn", () => {
      child.unref();
      resolve(true);
    });
  });

/**
 * Opens an `https://github.com/` URL in the system browser. Returns `false` (and opens nothing)
 * for any other URL or when the opener could not start. Failing to open is never an error: the
 * caller always prints the URL as well.
 */
export async function openGitHubUrl(
  url: string,
  options: { platform?: NodeJS.Platform; spawn?: SpawnOpener } = {},
): Promise<boolean> {
  const opener = openerCommandFor(options.platform ?? process.platform, url);
  if (opener === null) return false;
  return (options.spawn ?? spawnOpener)(opener.command, opener.args).catch(() => false);
}
