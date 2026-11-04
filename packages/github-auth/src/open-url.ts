import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
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

/** How long the opener may take to report a failure (a non-zero exit) before it counts as opened. */
export const OPENER_GRACE_MS = 1500;

/**
 * Starts the opener detached, without a shell, ignoring its output. Waits up to
 * `OPENER_GRACE_MS` for it to exit: a non-zero exit (xdg-open without a browser) is a failure;
 * still running, or exit 0, counts as opened. Never rejects.
 */
export const spawnOpener: SpawnOpener = (command, args) =>
  new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, [...args], { stdio: "ignore", detached: true, shell: false });
    } catch {
      resolve(false);
      return;
    }
    let timer: NodeJS.Timeout | undefined;
    child.once("error", () => {
      clearTimeout(timer);
      resolve(false);
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code === 0);
    });
    child.once("spawn", () => {
      child.unref();
      timer = setTimeout(() => resolve(true), OPENER_GRACE_MS);
      timer.unref();
    });
  });

/** Fixed absolute locations of `wslview` (wslu); never looked up through PATH. */
export const WSLVIEW_PATHS = ["/usr/bin/wslview", "/usr/local/bin/wslview"] as const;

/** The kernel files that name the Linux kernel; WSL kernels say "microsoft". */
const KERNEL_FILES = ["/proc/sys/kernel/osrelease", "/proc/version"] as const;

export type ReadTextFile = (path: string) => Promise<string>;

const readUtf8: ReadTextFile = (file) => readFile(file, "utf8");

/** Whether this Linux runs under WSL (a kernel release or version containing "microsoft"). */
export async function isWsl(readText: ReadTextFile = readUtf8): Promise<boolean> {
  for (const file of KERNEL_FILES) {
    try {
      if (/microsoft/i.test(await readText(file))) return true;
    } catch {
      // Not readable here (not Linux, or a sandbox): try the next file.
    }
  }
  return false;
}

/**
 * Opens an `https://github.com/` URL in the system browser. Returns `false` (and opens nothing)
 * for any other URL or when the opener could not start or exited with an error. On WSL only
 * `wslview` (from fixed absolute paths) is tried, because `xdg-open` there usually has no
 * browser. Failing to open is never an error: the caller always prints the URL as well.
 */
export async function openGitHubUrl(
  url: string,
  options: {
    platform?: NodeJS.Platform;
    spawn?: SpawnOpener;
    env?: NodeJS.ProcessEnv;
    readText?: ReadTextFile;
  } = {},
): Promise<boolean> {
  const platform = options.platform ?? process.platform;
  const opener = openerCommandFor(platform, url, options.env);
  if (opener === null) return false;
  const run = options.spawn ?? spawnOpener;
  if (platform === "linux" && (await isWsl(options.readText))) {
    for (const command of WSLVIEW_PATHS) {
      if (await run(command, [url]).catch(() => false)) return true;
    }
    return false;
  }
  return run(opener.command, opener.args).catch(() => false);
}
