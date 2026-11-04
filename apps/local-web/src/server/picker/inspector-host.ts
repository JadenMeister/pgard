import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { windowsSystemRoot } from "../open-local-url.js";
import { PICKER_LIMITS, type ChildMessage, type InspectorJob } from "./protocol.js";
import { validateChildMessage } from "./validate-message.js";

/**
 * Runs inspector jobs in a child process: the directory walk, the inspection of candidates
 * (including every Git call) and the identity re-checks.
 *
 * Why a child process and not a `worker_threads` Worker: a Worker shares the process's libuv
 * threadpool (4 threads by default) with the dashboard's own fs, DNS and crypto work. A `stat` on
 * a dead NFS mount can hold a threadpool thread forever; `worker.terminate()` stops JavaScript
 * but cannot free a thread blocked in a syscall, so four hung calls would freeze the dashboard.
 * A child process has its own threadpool.
 *
 * The child is started detached, so it leads its own process group, with an allowlisted
 * environment, no token, no stdout or stderr and no IPC beyond a JSON channel whose messages are
 * validated. On the hard deadline, on cancel and on shutdown the whole group gets `SIGKILL`,
 * which also ends the Git grandchildren. A process stuck in uninterruptible I/O survives `SIGKILL`
 * until the call returns: such children are counted, and past
 * `PICKER_LIMITS.maxOutstandingChildren` a new job is refused (`busy`).
 */

export type JobOutcome =
  | { status: "finished" }
  | { status: "killed"; reason: "deadline" | "cancelled" | "shutdown" }
  | { status: "failed" };

export interface RunningJob {
  result: Promise<JobOutcome>;
  /** Kills the child's process group. */
  cancel: () => void;
}

export interface InspectorHost {
  /** `null` when too many earlier children are stuck in the operating system. */
  run: (
    job: InspectorJob,
    options: { hardMs: number; onMessage: (message: ChildMessage) => void },
  ) => RunningJob | null;
  /** Kills every child's process group (server shutdown). */
  stopAll: () => void;
  /** Children that were killed but have not exited yet. */
  outstandingCount: () => number;
}

/** The only variables the child receives. Never a token, never a `PGARD_*` variable. */
export function inspectorEnvironment(
  source: Readonly<Record<string, string | undefined>>,
  platform: string = process.platform,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"]) {
    const value = source[key];
    if (value !== undefined) env[key] = value;
  }
  if (platform === "win32") {
    // The Git calls and Node need the system folder and a temp folder to start. `SystemRoot` is
    // passed only as a plain drive path (never a UNC or `..`); `windir` is the same folder.
    const root = windowsSystemRoot(source);
    env.SystemRoot = root;
    env.windir = root;
    for (const key of ["TEMP", "TMP", "USERPROFILE"]) {
      const value = source[key];
      if (value !== undefined) env[key] = value;
    }
  }
  env.NoDefaultCurrentDirectoryInExePath = "1";
  return env;
}

export type SpawnInspector = (entry: string, env: Record<string, string>) => ChildProcess;

const defaultSpawn: SpawnInspector = (entry, env) =>
  spawn(process.execPath, [entry], {
    detached: true,
    shell: false,
    windowsHide: true,
    // IPC is the only channel: nothing the child prints can leak.
    stdio: ["ignore", "ignore", "ignore", "ipc"],
    env,
    cwd: "/",
  });

/**
 * Where the child's script lives: next to this module when built, else the built copy under
 * `dist` (tests run the sources). The packed CLI rewrites this to its `inspector.js` bundle.
 */
export function resolveInspectorEntry(): string {
  const beside = fileURLToPath(new URL("./inspector-child.js", import.meta.url));
  if (existsSync(beside)) return beside;
  return beside.replace(/[\\/]src[\\/]server[\\/]/, "/dist/server/");
}

export interface InspectorHostOptions {
  entry?: string;
  spawnChild?: SpawnInspector;
  /** Sends `SIGKILL` to a process group (negative pid). Injectable for tests. */
  killGroup?: (pid: number) => void;
  env?: Readonly<Record<string, string | undefined>>;
  maxLiveChildren?: number;
}

/** `%SystemRoot%\System32\taskkill.exe`, absolute (never searched for). */
export function taskkillPath(env: Readonly<Record<string, string | undefined>>): string {
  return path.win32.join(windowsSystemRoot(env), "System32", "taskkill.exe");
}

/**
 * Ends the child and everything it started. POSIX: `SIGKILL` to the process group. Windows has
 * no process groups: `taskkill /T /F` ends the whole tree (the Git grandchildren). It runs before
 * the child itself is killed, because the tree is found through the parent. It runs
 * asynchronously (the event loop is never blocked) and, when several children are stopped at
 * once (shutdown), in parallel; the plain kill is the fallback if `taskkill` fails.
 */
function killProcessGroup(pid: number): void {
  if (process.platform === "win32") {
    try {
      const killer = spawn(taskkillPath(process.env), ["/T", "/F", "/PID", String(pid)], {
        shell: false,
        stdio: "ignore",
        windowsHide: true,
        timeout: 5_000,
      });
      killer.once("error", () => killPlain(pid));
      killer.once("exit", (code) => {
        if (code !== 0) killPlain(pid);
      });
      return;
    } catch {
      // Fall through to the plain kill.
    }
  }
  killPlain(pid);
}

function killPlain(pid: number): void {
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
}

export function createInspectorHost(options: InspectorHostOptions = {}): InspectorHost {
  const entry = options.entry ?? resolveInspectorEntry();
  const spawnChild = options.spawnChild ?? defaultSpawn;
  const killGroup = options.killGroup ?? killProcessGroup;
  const maxLive = options.maxLiveChildren ?? 4;
  type KillReason = "deadline" | "cancelled" | "shutdown";
  const live = new Set<{ kill: (reason: KillReason) => void }>();
  /** Killed, but the `exit` event has not arrived: possibly stuck in uninterruptible I/O. */
  const outstanding = new Set<ChildProcess>();

  return {
    outstandingCount: () => outstanding.size,
    stopAll: () => {
      for (const entry of [...live]) entry.kill("shutdown");
    },
    run: (job, { hardMs, onMessage }) => {
      if (outstanding.size >= PICKER_LIMITS.maxOutstandingChildren || live.size >= maxLive) {
        return null;
      }
      let child: ChildProcess;
      try {
        child = spawnChild(entry, inspectorEnvironment(options.env ?? process.env));
      } catch {
        return { result: Promise.resolve({ status: "failed" }), cancel: () => undefined };
      }
      let settle: (outcome: JobOutcome) => void = () => undefined;
      const result = new Promise<JobOutcome>((resolve) => {
        settle = resolve;
      });
      let isSettled = false;
      const handle = {
        kill: (reason: KillReason) => {
          if (isSettled) return;
          finish({ status: "killed", reason });
        },
      };
      const finish = (outcome: JobOutcome): void => {
        if (isSettled) return;
        isSettled = true;
        clearTimeout(timer);
        live.delete(handle);
        if (outcome.status !== "finished") {
          // A child that has already exited is never killed by pid: the number may be reused.
          const hasExited = child.exitCode !== null || child.signalCode !== null;
          if (typeof child.pid === "number" && !hasExited) killGroup(child.pid);
          // Counted until it really exits: a child stuck in the kernel survives `SIGKILL`.
          if (child.exitCode === null && child.signalCode === null) {
            outstanding.add(child);
            child.once("exit", () => outstanding.delete(child));
          }
        }
        try {
          child.disconnect();
        } catch {
          // The channel is already closed.
        }
        settle(outcome);
      };
      const timer = setTimeout(() => handle.kill("deadline"), hardMs);
      live.add(handle);
      child.unref();
      child.on("message", (raw: unknown) => {
        if (isSettled) return;
        const message = validateChildMessage(raw, job);
        if (message === null) return finish({ status: "failed" });
        onMessage(message);
        if (message.t === "done") finish({ status: "finished" });
      });
      child.on("error", () => finish({ status: "failed" }));
      // `disconnect` comes after every message was delivered; `exit` can come before the last
      // one, so it only starts a short grace period.
      child.on("disconnect", () => finish({ status: "failed" }));
      child.on("exit", () => setTimeout(() => finish({ status: "failed" }), 250).unref());
      try {
        child.send(job, (error) => {
          if (error !== null) finish({ status: "failed" });
        });
      } catch {
        finish({ status: "failed" });
      }
      return {
        result,
        cancel: () => handle.kill("cancelled"),
      };
    },
  };
}
