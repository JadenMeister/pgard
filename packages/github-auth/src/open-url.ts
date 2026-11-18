import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
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
 * macOS `open <url>`, Windows `%SystemRoot%\explorer.exe <url>`, WSL `wslview <url>` (from the
 * `wslu` package; `xdg-open` usually finds no browser there), everything else `xdg-open <url>`.
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
  isWsl = false,
): OpenerCommand | null {
  if (!OPENER_URL_CHARACTERS.test(url) || !isOpenableGitHubUrl(url)) return null;
  switch (platform) {
    case "darwin":
      return { command: "open", args: [url] };
    case "win32":
      return { command: windowsExplorerPath(env), args: [url] };
    default:
      return { command: isWsl ? "wslview" : "xdg-open", args: [url] };
  }
}

/** WSL kernels report "microsoft" (WSL2: `...-microsoft-standard-WSL2`; WSL1: `...-Microsoft`). */
export function isWslVersionText(text: string): boolean {
  return text.toLowerCase().includes("microsoft");
}

/** Whether this Linux runs under WSL, from `/proc/version`. `false` when it cannot be read. */
export function detectWsl(
  platform: NodeJS.Platform = process.platform,
  readVersion: () => string = () => readFileSync("/proc/version", "utf8"),
): boolean {
  if (platform !== "linux") return false;
  try {
    return isWslVersionText(readVersion());
  } catch {
    return false;
  }
}

/** How long an opener may run before it counts as started (a browser that stays open is fine). */
export const OPENER_EXIT_GRACE_MS = 2_000;

export type SpawnOpener = (
  command: string,
  args: readonly string[],
  options?: { checkExit?: boolean },
) => Promise<boolean>;

/**
 * Starts the opener detached, without a shell, ignoring its output. Never rejects. `false` when it
 * cannot start, and, with `checkExit`, when it exits non-zero within `OPENER_EXIT_GRACE_MS` (an
 * `xdg-open` without a browser does that). An opener still running after that counts as opened.
 */
export const spawnOpener: SpawnOpener = (command, args, options = {}) =>
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
      if (options.checkExit !== true) {
        resolve(true);
        return;
      }
      const timer = setTimeout(() => resolve(true), OPENER_EXIT_GRACE_MS);
      timer.unref();
      child.once("exit", (code) => {
        clearTimeout(timer);
        resolve(code === 0);
      });
    });
  });

/**
 * Opens an `https://github.com/` URL in the system browser. Returns `false` (and opens nothing)
 * for any other URL or when the opener could not start. Failing to open is never an error: the
 * caller always prints the URL as well.
 */
export async function openGitHubUrl(
  url: string,
  options: {
    platform?: NodeJS.Platform;
    spawn?: SpawnOpener;
    env?: NodeJS.ProcessEnv;
    /** Overrides the `/proc/version` check (tests). */
    isWsl?: boolean;
  } = {},
): Promise<boolean> {
  const platform = options.platform ?? process.platform;
  const isWsl = options.isWsl ?? detectWsl(platform);
  const opener = openerCommandFor(platform, url, options.env, isWsl);
  if (opener === null) return false;
  // `explorer.exe` exits 1 even when it opened the page, so only the others are judged by exit code.
  return (options.spawn ?? spawnOpener)(opener.command, opener.args, {
    checkExit: platform !== "win32",
  }).catch(() => false);
}
