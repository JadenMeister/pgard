import { spawn } from "node:child_process";
import path from "node:path";

/**
 * Opens PGARD's own local session URL in the default browser (#419). Deliberately separate from
 * the GitHub opener (`openGitHubUrl`, which opens only `https://github.com/` pages) and narrower:
 * the only URL it ever accepts is `http://127.0.0.1:<port>/` with an optional `#token=` fragment,
 * checked against `LOCAL_SESSION_URL` on every platform before anything is started. The opener
 * runs with a fixed argument vector and no shell.
 */
export const LOCAL_SESSION_URL = /^http:\/\/127\.0\.0\.1:\d+\/(#token=[A-Za-z0-9_-]+)?$/;

export type OpenSkipReason =
  /** `--no-open` or `--no-browser`. */
  | "disabled"
  /** stdout is not a terminal (piped, a service, a script). */
  | "no_terminal"
  /** `CI` is set. */
  | "ci"
  /** An SSH session: the browser would open on the other machine's screen, or not at all. */
  | "ssh"
  /** Linux and similar without `DISPLAY` or `WAYLAND_DISPLAY`. */
  | "no_display"
  /** The URL is not PGARD's own local URL (a bug, never user input). */
  | "bad_url"
  /** The opener could not be started. */
  | "failed";

export type OpenerPlan =
  { kind: "open"; command: string; args: string[] } | { kind: "skip"; reason: OpenSkipReason };

export interface OpenerEnvironment {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  isTerminal: boolean;
  isDisabled: boolean;
}

const isSet = (value: string | undefined): boolean => value !== undefined && value !== "";

/**
 * `%SystemRoot%\System32\rundll32.exe` as an absolute path (a bare name would be searched in the
 * current directory first). `SystemRoot` is trusted only as a plain drive path.
 */
export function windowsRundll32Path(env: Readonly<Record<string, string | undefined>>): string {
  const root = env.SystemRoot ?? env.SYSTEMROOT ?? "";
  const isTrusted = /^[A-Za-z]:\\[A-Za-z0-9 _.\\()-]*$/.test(root) && !root.includes("..");
  return path.win32.join(isTrusted ? root : "C:\\Windows", "System32", "rundll32.exe");
}

/** What would be started for `url`, or why nothing is. Pure: the platform and env are passed in. */
export function planLocalOpen(url: string, environment: OpenerEnvironment): OpenerPlan {
  const { platform, env } = environment;
  if (environment.isDisabled) return { kind: "skip", reason: "disabled" };
  if (!LOCAL_SESSION_URL.test(url)) return { kind: "skip", reason: "bad_url" };
  if (!environment.isTerminal) return { kind: "skip", reason: "no_terminal" };
  if (isSet(env.CI)) return { kind: "skip", reason: "ci" };
  switch (platform) {
    case "darwin":
      return { kind: "open", command: "/usr/bin/open", args: [url] };
    case "win32":
      // `url.dll,FileProtocolHandler` hands the URL to the default browser; the URL was checked
      // above and holds no character cmd or rundll32 would treat specially.
      return {
        kind: "open",
        command: windowsRundll32Path(env),
        args: ["url.dll,FileProtocolHandler", url],
      };
    default:
      if (isSet(env.SSH_CONNECTION) || isSet(env.SSH_TTY)) return { kind: "skip", reason: "ssh" };
      if (!isSet(env.DISPLAY) && !isSet(env.WAYLAND_DISPLAY)) {
        return { kind: "skip", reason: "no_display" };
      }
      return { kind: "open", command: "xdg-open", args: [url] };
  }
}

export type SpawnDetached = (command: string, args: readonly string[]) => Promise<boolean>;

/** Starts the opener detached, without a shell, ignoring its output. Never rejects. */
export const spawnDetached: SpawnDetached = (command, args) =>
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

export type OpenOutcome = { isOpened: true } | { isOpened: false; reason: OpenSkipReason };

/** Opens the local URL when `planLocalOpen` allows it. Failing to open is never an error. */
export async function openLocalUrl(
  url: string,
  environment: OpenerEnvironment,
  spawnOpener: SpawnDetached = spawnDetached,
): Promise<OpenOutcome> {
  const plan = planLocalOpen(url, environment);
  if (plan.kind === "skip") return { isOpened: false, reason: plan.reason };
  const isStarted = await spawnOpener(plan.command, plan.args).catch(() => false);
  return isStarted ? { isOpened: true } : { isOpened: false, reason: "failed" };
}
