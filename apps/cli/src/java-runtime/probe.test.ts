import path from "node:path";
import { describe, expect, it } from "vitest";
import { JAVA_OUTPUT_CAP_BYTES, JAVA_TIMEOUT_MS, readJavaVersionOutput } from "./probe.js";

type Callback = (
  error: (Error & { code?: unknown; killed?: boolean }) | null,
  stdout: string,
  stderr: string,
) => void;

interface Call {
  file: string;
  args: readonly string[];
  options: Record<string, unknown>;
}

/** A fake execFile: records the call and answers with `reply`. Never starts a process. */
function fake(reply: (callback: Callback) => void, calls: Call[] = []) {
  return (
    file: string,
    args: readonly string[],
    options: Record<string, unknown>,
    cb: Callback,
  ) => {
    calls.push({ file, args, options });
    reply(cb);
  };
}

function failure(code: unknown, extra: { killed?: boolean } = {}) {
  return Object.assign(new Error("boom"), { code, ...extra });
}

describe("readJavaVersionOutput", () => {
  it("runs `java -version` without a shell, with a timeout, a cap and a minimal environment", async () => {
    const calls: Call[] = [];
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin", GITHUB_TOKEN: "ghp_secret", HOME: "/home/me", JAVA_HOME: "" },
      platform: "linux",
      isFile: () => false,
      execFile: fake((cb) => cb(null, "", 'openjdk version "17.0.21"'), calls) as never,
    });
    expect(probe).toEqual({ status: "output", text: 'openjdk version "17.0.21"\n' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.file).toBe("java");
    expect(calls[0]?.args).toEqual(["-version"]);
    expect(calls[0]?.options["shell"]).toBe(false);
    expect(calls[0]?.options["timeout"]).toBe(JAVA_TIMEOUT_MS);
    expect(calls[0]?.options["maxBuffer"]).toBe(JAVA_OUTPUT_CAP_BYTES);
    expect(calls[0]?.options["env"]).toEqual({ PATH: "/usr/bin", JAVA_HOME: "" });
  });

  it("prefers JAVA_HOME/bin/java when that file exists, else PATH", async () => {
    const calls: Call[] = [];
    const home = path.join("/opt", "jdk");
    const wanted = path.join(home, "bin", "java");
    const run = (isFile: (file: string) => boolean, platform: NodeJS.Platform = "linux") =>
      readJavaVersionOutput({
        env: { PATH: "/usr/bin", JAVA_HOME: home },
        platform,
        isFile,
        execFile: fake((cb) => cb(null, "", "x"), calls) as never,
      });
    await run((file) => file === wanted);
    await run(() => false);
    await run((file) => file === path.join(home, "bin", "java.exe"), "win32");
    expect(calls.map((call) => call.file)).toEqual([
      wanted,
      "java",
      path.join(home, "bin", "java.exe"),
    ]);
  });

  it("reports no Java for ENOENT and for the macOS stub message", async () => {
    const missing = await readJavaVersionOutput({
      env: {},
      execFile: fake((cb) => cb(failure("ENOENT"), "", "")) as never,
    });
    expect(missing).toEqual({ status: "missing" });
    const stub = await readJavaVersionOutput({
      env: {},
      execFile: fake((cb) =>
        cb(failure(1), "", "The operation couldn't be completed. Unable to locate a Java Runtime."),
      ) as never,
    });
    expect(stub).toEqual({ status: "missing" });
  });

  it("reports a Java that cannot be run: permission denied, timeout, other errors", async () => {
    const run = (error: Error) =>
      readJavaVersionOutput({ env: {}, execFile: fake((cb) => cb(error, "", "")) as never });
    expect(await run(failure("EACCES"))).toEqual({ status: "failed", cause: "access" });
    expect(await run(failure(null, { killed: true }))).toEqual({
      status: "failed",
      cause: "timeout",
    });
    expect(await run(failure(1))).toEqual({ status: "failed", cause: "error" });
  });

  it("still reads the version of a non-zero exit that printed it", async () => {
    const probe = await readJavaVersionOutput({
      env: {},
      execFile: fake((cb) => cb(failure(1), "", 'openjdk version "21.0.13"')) as never,
    });
    expect(probe.status).toBe("output");
  });

  it("keeps only the capped output when the child printed too much", async () => {
    const big = "x".repeat(JAVA_OUTPUT_CAP_BYTES * 3);
    const probe = await readJavaVersionOutput({
      env: {},
      execFile: fake((cb) =>
        cb(failure("ERR_CHILD_PROCESS_STDIO_MAXBUFFER", { killed: true }), "", big),
      ) as never,
    });
    expect(probe.status).toBe("output");
    if (probe.status === "output")
      expect(probe.text.length).toBeLessThanOrEqual(JAVA_OUTPUT_CAP_BYTES);
  });

  it("never throws, even when execFile itself throws", async () => {
    const probe = await readJavaVersionOutput({
      env: {},
      execFile: (() => {
        throw new Error("spawn exploded");
      }) as never,
    });
    expect(probe).toEqual({ status: "failed", cause: "error" });
  });
});
