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
    env: NodeJS.ProcessEnv;
    encoding: "utf8";
  },
  callback: (error: ExecError | null, stdout: string, stderr: string) => void,
) => unknown;

export interface JavaProbeOptions {
  env?: Readonly<Record<string, string | undefined>>;
  platform?: NodeJS.Platform;
  /** Injected in tests; the default is `node:child_process.execFile`. */
  execFile?: ExecFileFn;
  isFile?: (file: string) => boolean;
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
 * Reads the Java runtime's own version text: `JAVA_HOME/bin/java` first when that file exists,
 * else `java` from PATH. `execFile` with an argument array (no shell), a 5 s timeout that kills
 * the child and a 64 KiB output cap. Never throws.
 */
export function readJavaVersionOutput(options: JavaProbeOptions = {}): Promise<JavaProbe> {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const exec = options.execFile ?? (nodeExecFile as unknown as ExecFileFn);
  const isFile = options.isFile ?? isFileDefault;
  const program = platform === "win32" ? "java.exe" : "java";
  const javaHome = env["JAVA_HOME"]?.trim();
  let file = program;
  if (javaHome !== undefined && javaHome.length > 0) {
    const candidate = path.join(javaHome, "bin", program);
    if (isFile(candidate)) file = candidate;
  }
  return new Promise<JavaProbe>((resolve) => {
    try {
      exec(
        file,
        ["-version"],
        {
          timeout: JAVA_TIMEOUT_MS,
          maxBuffer: JAVA_OUTPUT_CAP_BYTES,
          shell: false,
          windowsHide: true,
          env: minimalEnv(env, platform),
          encoding: "utf8",
        },
        (error, stdout, stderr) => {
          const text = `${stderr ?? ""}\n${stdout ?? ""}`.slice(0, JAVA_OUTPUT_CAP_BYTES);
          if (error === null) {
            resolve(classify(text));
            return;
          }
          const code = error.code;
          if (code === "ENOENT") resolve({ status: "missing" });
          else if (code === "EACCES" || code === "EPERM") {
            resolve({ status: "failed", cause: "access" });
          } else if (code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") resolve(classify(text));
          else if (error.killed === true) resolve({ status: "failed", cause: "timeout" });
          // A non-zero exit that still printed the version text is read like a normal run.
          else if (text.trim().length > 0) resolve(classify(text));
          else resolve({ status: "failed", cause: "error" });
        },
      );
    } catch {
      resolve({ status: "failed", cause: "error" });
    }
  });
}
