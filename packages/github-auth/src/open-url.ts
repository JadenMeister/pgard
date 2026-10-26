import { spawn } from "node:child_process";
import path from "node:path";
import { isOpenableGitHubUrl } from "./app-install.js";

/** Every character a URL handed to the system opener may contain. */
export const OPENER_URL_CHARACTERS = /^[A-Za-z0-9/_.?=&%:-]+$/;

export interface OpenerCommand {
  command: string;
  args: string[];
}

/**
 * `%SystemRoot%\explorer.exe` as an absolute path, because Windows resolves a bare name against
 * the current directory first. SystemRoot is trusted only when it is a plain absolute drive
 * path; otherwise `C:\Windows` is used.
 */
export function windowsExplorerPath(env: NodeJS.ProcessEnv = process.env): string {
  const root = env.SystemRoot ?? env.SYSTEMROOT ?? "";
  const isTrusted = /^[A-Za-z]:\\[A-Za-z0-9 _.\\()-]*$/.test(root) && !root.includes("..");
  return path.win32.join(isTrusted ? root : "C:\\Windows", "explorer.exe");
}

/**
 * The platform's URL opener with a fixed argument vector (never a shell string):
 * macOS `open <url>`, Windows `%SystemRoot%\explorer.exe <url>`, everything else `xdg-open <url>`.
 *
 * Windows uses `explorer.exe` rather than `cmd /c start`, because cmd would parse `&` in the
 * query string as a command separator. `null` when the URL is not an `https://github.com/` URL,
 * or when it holds any character outside `OPENER_URL_CHARACTERS` (defence in depth: the URLs
 * PGARD opens, the device page and the percent-encoded install link, never need more).
 */
export function openerCommandFor(
  platform: NodeJS.Platform,
  url: string,
  env: NodeJS.ProcessEnv = process.env,
): OpenerCommand | null {
  if (!OPENER_URL_CHARACTERS.test(url) || !isOpenableGitHubUrl(url)) return null;
  switch (platform) {
    case "darwin":
      return { command: "open", args: [url] };
    case "win32":
      return { command: windowsExplorerPath(env), args: [url] };
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
  options: { platform?: NodeJS.Platform; spawn?: SpawnOpener; env?: NodeJS.ProcessEnv } = {},
): Promise<boolean> {
  const opener = openerCommandFor(options.platform ?? process.platform, url, options.env);
  if (opener === null) return false;
  return (options.spawn ?? spawnOpener)(opener.command, opener.args).catch(() => false);
}
