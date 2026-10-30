import { spawn } from "node:child_process";
import path from "node:path";
import { createRedirectFile, isOurRedirectFile, type RedirectFile } from "./redirect-file.js";

/**
 * Opens PGARD's own local page in the default browser (#419). Deliberately separate from the
 * GitHub opener (`openGitHubUrl`, which opens only `https://github.com/` pages) and narrower.
 *
 * The one-time link is never an opener argument (process arguments are visible to other local
 * users): it is written into a private redirect file (`redirect-file.ts`), and the opener gets
 * only that file's path, checked to be exactly our file in our own temp directory. The link
 * itself must match `LOCAL_SESSION_URL`. The opener runs with a fixed argument vector and no
 * shell.
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
  /** The link or the redirect file path is not ours (a bug, never user input). */
  | "bad_url"
  /** The redirect file could not be written, or the opener failed. */
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

/** Why the browser must not be opened here, or `null`. Pure: the platform and env are passed in. */
export function openSkipReason(environment: OpenerEnvironment): OpenSkipReason | null {
  const { platform, env } = environment;
  if (environment.isDisabled) return "disabled";
  if (!environment.isTerminal) return "no_terminal";
  if (isSet(env.CI)) return "ci";
  // On every platform: over SSH (also into a Mac) the browser would open, and spend the link,
  // on the physical screen of the other machine.
  if (isSet(env.SSH_CONNECTION) || isSet(env.SSH_TTY)) return "ssh";
  if (platform !== "darwin" && platform !== "win32") {
    if (!isSet(env.DISPLAY) && !isSet(env.WAYLAND_DISPLAY)) return "no_display";
  }
  return null;
}

/**
 * What would be started to open the redirect file (which must be our own file, in our own
 * folder, in our redirect root), or why nothing is.
 */
export function planLocalOpen(
  redirect: Pick<RedirectFile, "file" | "dir" | "root">,
  environment: OpenerEnvironment,
): OpenerPlan {
  const filePath = redirect.file;
  const reason = openSkipReason(environment);
  if (reason !== null) return { kind: "skip", reason };
  const { platform, env } = environment;
  if (!isOurRedirectFile(filePath, redirect.dir, platform, redirect.root)) {
    return { kind: "skip", reason: "bad_url" };
  }
  switch (platform) {
    case "darwin":
      return { kind: "open", command: "/usr/bin/open", args: [filePath] };
    case "win32":
      // `url.dll,FileProtocolHandler` opens an .html file in the default browser.
      return {
        kind: "open",
        command: windowsRundll32Path(env),
        args: ["url.dll,FileProtocolHandler", filePath],
      };
    default:
      return { kind: "open", command: "xdg-open", args: [filePath] };
  }
}

export type SpawnDetached = (command: string, args: readonly string[]) => Promise<boolean>;

/** How long the opener may take to report a failure (a non-zero exit) before it counts as opened. */
export const OPENER_GRACE_MS = 1500;

/**
 * Starts the opener detached, without a shell, ignoring its output. Waits up to
 * `OPENER_GRACE_MS` for it to exit: a non-zero exit (xdg-open without a browser, `open` without
 * an app) is a failure; still running, or exit 0, counts as opened. Never rejects.
 */
export const spawnDetached: SpawnDetached = (command, args) =>
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

export type OpenOutcome = { isOpened: true } | { isOpened: false; reason: OpenSkipReason };

export interface OpenLocalDeps {
  spawn?: SpawnDetached;
  createRedirect?: (url: string) => Promise<RedirectFile>;
}

/**
 * Opens the local link when allowed: writes the redirect file, opens it, and returns it so the
 * caller deletes it (after the exchange, on expiry, on exit). Nothing is written when the
 * browser is not opened, and the file is deleted again when opening failed. Failing to open is
 * never an error.
 */
export async function openLocalUrl(
  url: string,
  environment: OpenerEnvironment,
  deps: OpenLocalDeps = {},
): Promise<{ outcome: OpenOutcome; redirect: RedirectFile | null }> {
  const skip = (reason: OpenSkipReason) => ({
    outcome: { isOpened: false as const, reason },
    redirect: null,
  });
  const reason = openSkipReason(environment);
  if (reason !== null) return skip(reason);
  if (!LOCAL_SESSION_URL.test(url) || !url.includes("#token=")) return skip("bad_url");
  let redirect: RedirectFile;
  try {
    redirect = await (deps.createRedirect ?? createRedirectFile)(url);
  } catch {
    return skip("failed");
  }
  const plan = planLocalOpen(redirect, environment);
  if (plan.kind === "skip") {
    await redirect.remove();
    return skip(plan.reason);
  }
  const isStarted = await (deps.spawn ?? spawnDetached)(plan.command, plan.args).catch(() => false);
  if (!isStarted) {
    await redirect.remove();
    return skip("failed");
  }
  return { outcome: { isOpened: true }, redirect };
}
