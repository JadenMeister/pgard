import { execFile as nodeExecFile } from "node:child_process";
import { statSync } from "node:fs";
import path from "node:path";

/**
 * What running `java -version` gave. `missing`: no Java found. `failed`: one was found but could
 * not be run in time (or at all). `output`: the text it printed (stdout and stderr together).
 */
export type JavaProbe =
  | { status: "missing" }
  | { status: "failed"; cause: "timeout" | "access" | "error" }
  | { status: "output"; text: string };

export const JAVA_TIMEOUT_MS = 5000;
export const JAVA_OUTPUT_CAP_BYTES = 64 * 1024;

type ExecError = Error & { code?: unknown; killed?: boolean };

type ExecFileFn = (
  file: string,
  args: readonly string[],
  options: {
    timeout: number;
    maxBuffer: number;
    shell: false;
    windowsHide: true;
    killSignal: "SIGKILL";
    detached: boolean;
    env: NodeJS.ProcessEnv;
    encoding: "utf8";
  },
  callback: (error: ExecError | null, stdout: string, stderr: string) => void,
) =>
  { pid?: number | undefined; kill?: (signal?: NodeJS.Signals) => boolean } | undefined | unknown;

export interface JavaProbeOptions {
  env?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
  /** Injected in tests; the default is `node:child_process.execFile`. */
  execFile?: ExecFileFn;
  isFile?: (file: string) => boolean;
  /** The process's own current directory (never searched on Windows). Test hook. */
  cwd?: string;
  /** Test hook; defaults to 5 seconds. */
  timeoutMs?: number;
}

function isFileDefault(file: string): boolean {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
}

/** Only what Java needs to start: no tokens or other secrets are passed to the child. */
function minimalEnv(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
): NodeJS.ProcessEnv {
  const kept: NodeJS.ProcessEnv = {};
  const names =
    platform === "win32" ? ["PATH", "Path", "JAVA_HOME", "SystemRoot"] : ["PATH", "JAVA_HOME"];
  for (const name of names) {
    const value = env[name];
    if (value !== undefined) kept[name] = value;
  }
  return kept;
}

/** The macOS `/usr/bin/java` stub prints this when no JDK is installed: that is "no Java". */
function classify(text: string): JavaProbe {
  const lower = text.toLowerCase();
  if (
    lower.includes("unable to locate a java runtime") ||
    lower.includes("no java runtime present")
  ) {
    return { status: "missing" };
  }
  return { status: "output", text };
}

/**
 * Windows PATH entries a search may use, as in `trustedPathEntries` of `@pgard/git-history` (the
 * same rules; copied because the CLI does not depend on that package): quotes stripped, only
 * drive-absolute entries, none with characters Windows forbids.
 */
function trustedPathEntries(pathValue: string): string[] {
  const entries: string[] = [];
  for (const raw of pathValue.split(";")) {
    let entry = raw.trim();
    if (entry.length >= 2 && entry.startsWith('"') && entry.endsWith('"')) {
      entry = entry.slice(1, -1).trim();
    }
    if (!/^[A-Za-z]:[\\/]/.test(entry) || /["<>|*?\0]/.test(entry)) continue;
    entries.push(path.win32.normalize(entry));
  }
  return entries;
}

function isSameOrInside(candidate: string, base: string): boolean {
  const relative = path.win32.relative(path.win32.resolve(base), path.win32.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.win32.isAbsolute(relative));
}

/**
 * The Java program to run, as an absolute path, or `null` when there is none. `JAVA_HOME/bin/java`
 * counts only when JAVA_HOME is absolute and the file exists. Otherwise PATH is walked by hand:
 * empty and relative entries (which mean "the current directory") are skipped, and on Windows
 * so is every entry inside the current directory. A bare `java` is never spawned, because the
 * system would then look in the current directory first (a scanned repository could plant one).
 */
export function resolveJavaExecutable(options: JavaProbeOptions = {}): string | null {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const isFile = options.isFile ?? isFileDefault;
  const isWindows = platform === "win32";
  const lib = isWindows ? path.win32 : path.posix;
  const program = isWindows ? "java.exe" : "java";
  const javaHome = env["JAVA_HOME"]?.trim();
  if (javaHome !== undefined && javaHome.length > 0) {
    const homes = isWindows
      ? trustedPathEntries(javaHome)
      : lib.isAbsolute(javaHome)
        ? [javaHome]
        : [];
    for (const home of homes) {
      const candidate = lib.join(home, "bin", program);
      if (isFile(candidate)) return candidate;
    }
  }
  const pathValue = (isWindows ? (env["Path"] ?? env["PATH"] ?? env["path"]) : env["PATH"]) ?? "";
  const cwd = options.cwd ?? process.cwd();
  const directories = isWindows
    ? trustedPathEntries(pathValue).filter((entry) => !isSameOrInside(entry, cwd))
    : pathValue.split(":").filter((entry) => entry.length > 0 && lib.isAbsolute(entry));
  for (const directory of directories) {
    const candidate = lib.join(directory, program);
    if (isFile(candidate)) return candidate;
  }
  return null;
}

/**
 * Reads the Java runtime's own version text: `JAVA_HOME/bin/java` first, else `java` from the
 * trusted PATH entries. `execFile` with an argument array (no shell), SIGKILL after 5 s, a 64 KiB
 * output cap, and a timer of its own that answers "timeout" even if the callback never fires (a
 * child that ignores signals, or a grandchild that keeps the pipes open). On POSIX the child
 * leads its own process group and the whole group is killed; on Windows only the child is.
 * Never throws.
 */
export function readJavaVersionOutput(options: JavaProbeOptions = {}): Promise<JavaProbe> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const exec = options.execFile ?? (nodeExecFile as unknown as ExecFileFn);
  const timeoutMs = options.timeoutMs ?? JAVA_TIMEOUT_MS;
  const file = resolveJavaExecutable(options);
  if (file === null) return Promise.resolve({ status: "missing" });
  return new Promise<JavaProbe>((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    let child:
      { pid?: number | undefined; kill?: (signal?: NodeJS.Signals) => boolean } | undefined;
    const finish = (probe: JavaProbe): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve(probe);
    };
    const killChild = (): void => {
      try {
        if (platform !== "win32" && child?.pid !== undefined) process.kill(-child.pid, "SIGKILL");
        else child?.kill?.("SIGKILL");
      } catch {
        try {
          child?.kill?.("SIGKILL");
        } catch {
          // already gone
        }
      }
    };
    try {
      child = exec(
        file,
        ["-version"],
        {
          timeout: timeoutMs,
          maxBuffer: JAVA_OUTPUT_CAP_BYTES,
          shell: false,
          windowsHide: true,
          killSignal: "SIGKILL",
          detached: platform !== "win32",
          env: minimalEnv(env, platform),
          encoding: "utf8",
        },
        (error, stdout, stderr) => {
          const text = `${stderr ?? ""}\n${stdout ?? ""}`.slice(0, JAVA_OUTPUT_CAP_BYTES);
          if (error === null) {
            finish(classify(text));
            return;
          }
          const code = error.code;
          if (code === "ENOENT") finish({ status: "missing" });
          else if (code === "EACCES" || code === "EPERM") {
            finish({ status: "failed", cause: "access" });
          } else if (code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") finish(classify(text));
          else if (error.killed === true) finish({ status: "failed", cause: "timeout" });
          // A non-zero exit that still printed the version text is read like a normal run.
          else if (text.trim().length > 0) finish(classify(text));
          else finish({ status: "failed", cause: "error" });
        },
      ) as typeof child;
      if (!settled) {
        timer = setTimeout(() => {
          killChild();
          finish({ status: "failed", cause: "timeout" });
        }, timeoutMs + 250);
        timer.unref();
      }
    } catch {
      finish({ status: "failed", cause: "error" });
    }
  });
}
