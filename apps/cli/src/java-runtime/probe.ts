import { spawn as nodeSpawn } from "node:child_process";
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

/** The part of a child process the probe uses (a fake in tests). */
export interface JavaChild {
  stdout: NodeJS.ReadableStream | null;
  stderr: NodeJS.ReadableStream | null;
  kill: (signal?: NodeJS.Signals) => boolean;
  once: (event: string, listener: (...args: never[]) => void) => unknown;
}

export type SpawnFn = (
  file: string,
  args: readonly string[],
  options: {
    stdio: ["ignore", "pipe", "pipe"];
    shell: false;
    windowsHide: true;
    env: NodeJS.ProcessEnv;
  },
) => JavaChild;

export interface JavaProbeOptions {
  env?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
  /** Injected in tests; the default is `node:child_process.spawn`. */
  spawn?: SpawnFn;
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
 * trusted PATH entries, as an absolute path (see `resolveJavaExecutable`). `spawn` with an
 * argument array (no shell), no stdin (reads end at once), stdout and stderr collected up to
 * 64 KiB (the child is killed when it prints more), and `SIGKILL` of the direct child after 5 s
 * or when PGARD exits. A timer answers "timeout" even if the child never closes. Only the direct
 * child is killed. Never throws.
 */
export function readJavaVersionOutput(options: JavaProbeOptions = {}): Promise<JavaProbe> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const spawnChild = options.spawn ?? (nodeSpawn as unknown as SpawnFn);
  const timeoutMs = options.timeoutMs ?? JAVA_TIMEOUT_MS;
  const file = resolveJavaExecutable(options);
  if (file === null) return Promise.resolve({ status: "missing" });
  return new Promise<JavaProbe>((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    let child: JavaChild | undefined;
    const killOnExit = (): void => {
      try {
        child?.kill("SIGKILL");
      } catch {
        // already gone
      }
    };
    const finish = (probe: JavaProbe): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      process.removeListener("exit", killOnExit);
      resolve(probe);
    };
    try {
      child = spawnChild(file, ["-version"], {
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
        windowsHide: true,
        env: minimalEnv(env, platform),
      });
      process.once("exit", killOnExit);
      const stderrChunks: string[] = [];
      const stdoutChunks: string[] = [];
      let size = 0;
      let isCapped = false;
      const text = (): string =>
        `${stderrChunks.join("")}\n${stdoutChunks.join("")}`.slice(0, JAVA_OUTPUT_CAP_BYTES);
      const collect = (into: string[]) => (chunk: unknown) => {
        if (isCapped) return;
        const piece = String(chunk);
        size += piece.length;
        into.push(piece);
        if (size > JAVA_OUTPUT_CAP_BYTES) {
          isCapped = true;
          killOnExit();
          finish(classify(text()));
        }
      };
      child.stdout?.on("data", collect(stdoutChunks));
      child.stderr?.on("data", collect(stderrChunks));
      child.stdout?.on("error", () => undefined);
      child.stderr?.on("error", () => undefined);
      child.once("error", ((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") finish({ status: "missing" });
        else if (error.code === "EACCES" || error.code === "EPERM") {
          finish({ status: "failed", cause: "access" });
        } else finish({ status: "failed", cause: "error" });
      }) as never);
      child.once("close", ((code: number | null) => {
        const output = text();
        if (code === 0) finish(classify(output));
        // A non-zero exit that still printed the version text is read like a normal run.
        else if (output.trim().length > 0) finish(classify(output));
        else finish({ status: "failed", cause: "error" });
      }) as never);
      timer = setTimeout(() => {
        killOnExit();
        finish({ status: "failed", cause: "timeout" });
      }, timeoutMs);
      timer.unref();
    } catch {
      killOnExit();
      finish({ status: "failed", cause: "error" });
    }
  });
}
