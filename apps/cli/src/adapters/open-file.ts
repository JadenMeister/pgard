import { spawn } from "node:child_process";
import path from "node:path";

export interface OpenerCommand {
  command: string;
  args: string[];
}

/** Only the two report formats are ever opened, and only as an absolute path. */
const OPENABLE_REPORT = /\.(html|pdf)$/i;

/** `%SystemRoot%\explorer.exe` as an absolute path (a bare name would be searched in the cwd). */
function windowsExplorerPath(env: NodeJS.ProcessEnv): string {
  const root = env.SystemRoot ?? env.SYSTEMROOT ?? "";
  const isTrusted = /^[A-Za-z]:\\[A-Za-z0-9 _.\\()-]*$/.test(root) && !root.includes("..");
  return path.win32.join(isTrusted ? root : "C:\\Windows", "explorer.exe");
}

/** A Windows path must start with a drive letter or a UNC prefix. */
const WINDOWS_ABSOLUTE = /^(?:[A-Za-z]:\\|\\\\[^\\/]+[\\/][^\\/]+)/;

/**
 * The platform's file opener with a fixed argument vector (never a shell string): macOS
 * `open`, Windows `explorer.exe`, everything else `xdg-open`. `null` unless `filePath` is an
 * absolute path to a `.html` or `.pdf` file that does not start with `-`.
 */
export function openerCommandForFile(
  platform: NodeJS.Platform,
  filePath: string,
  env: NodeJS.ProcessEnv = process.env,
): OpenerCommand | null {
  const isAbsolute =
    platform === "win32" ? WINDOWS_ABSOLUTE.test(filePath) : path.posix.isAbsolute(filePath);
  if (!isAbsolute || filePath.startsWith("-") || !OPENABLE_REPORT.test(filePath)) return null;
  if (/[\0\r\n]/.test(filePath)) return null;
  switch (platform) {
    case "darwin":
      return { command: "/usr/bin/open", args: [filePath] };
    case "win32":
      return { command: windowsExplorerPath(env), args: [filePath] };
    default:
      return { command: "xdg-open", args: [filePath] };
  }
}

export type SpawnOpener = (command: string, args: readonly string[]) => Promise<boolean>;

const spawnOpener: SpawnOpener = (command, args) =>
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

/** Opens a saved report with the system default program. Never rejects; `false` = not opened. */
export async function openLocalFile(
  filePath: string,
  options: { platform?: NodeJS.Platform; spawn?: SpawnOpener; env?: NodeJS.ProcessEnv } = {},
): Promise<boolean> {
  const opener = openerCommandForFile(options.platform ?? process.platform, filePath, options.env);
  if (opener === null) return false;
  return (options.spawn ?? spawnOpener)(opener.command, opener.args).catch(() => false);
}
