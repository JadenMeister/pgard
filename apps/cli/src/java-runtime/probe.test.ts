import { chmod, mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  JAVA_OUTPUT_CAP_BYTES,
  JAVA_TIMEOUT_MS,
  readJavaVersionOutput,
  resolveJavaExecutable,
} from "./probe.js";

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
    return undefined;
  };
}

function failure(code: unknown, extra: { killed?: boolean } = {}) {
  return Object.assign(new Error("boom"), { code, ...extra });
}

/** Only these absolute files "exist". */
const exists =
  (...files: string[]) =>
  (file: string) =>
    files.includes(file);

describe("resolveJavaExecutable", () => {
  it("uses JAVA_HOME/bin/java when it is absolute and the file exists, else the PATH", () => {
    const home = "/opt/jdk";
    const env = { PATH: "/usr/bin:/bin", JAVA_HOME: home };
    expect(
      resolveJavaExecutable({
        env,
        platform: "linux",
        isFile: exists("/opt/jdk/bin/java", "/usr/bin/java"),
      }),
    ).toBe("/opt/jdk/bin/java");
    expect(resolveJavaExecutable({ env, platform: "linux", isFile: exists("/usr/bin/java") })).toBe(
      "/usr/bin/java",
    );
  });

  it("ignores a relative JAVA_HOME", () => {
    const env = { PATH: "/usr/bin", JAVA_HOME: "jdk" };
    expect(
      resolveJavaExecutable({
        env,
        platform: "linux",
        isFile: exists("jdk/bin/java", "/usr/bin/java"),
      }),
    ).toBe("/usr/bin/java");
    expect(
      resolveJavaExecutable({
        env: { PATH: "", JAVA_HOME: "../jdk" },
        platform: "linux",
        isFile: () => true,
      }),
    ).toBeNull();
  });

  it("skips empty and relative PATH entries (they mean the current directory)", () => {
    for (const pathValue of [".:/usr/bin", "/usr/bin:", ":/usr/bin", "bin::/usr/bin", "./bin:."]) {
      const seen: string[] = [];
      const found = resolveJavaExecutable({
        env: { PATH: pathValue },
        platform: "linux",
        isFile: (file) => {
          seen.push(file);
          return file === "/usr/bin/java" || !path.isAbsolute(file);
        },
      });
      expect(
        seen.every((file) => path.isAbsolute(file)),
        pathValue,
      ).toBe(true);
      expect(found === "/usr/bin/java" || found === null, pathValue).toBe(true);
    }
    expect(
      resolveJavaExecutable({ env: { PATH: ".::" }, platform: "linux", isFile: () => true }),
    ).toBeNull();
  });

  it("is null when there is no PATH or nothing is found", () => {
    expect(resolveJavaExecutable({ env: {}, platform: "linux", isFile: () => true })).toBeNull();
    expect(
      resolveJavaExecutable({ env: { PATH: "/usr/bin" }, platform: "linux", isFile: () => false }),
    ).toBeNull();
  });

  it("on Windows needs java.exe from an absolute PATH entry outside the current directory", () => {
    const run = (env: Record<string, string>, isFile: (file: string) => boolean) =>
      resolveJavaExecutable({
        env,
        platform: "win32",
        cwd: "C:\\work\\repo",
        isFile,
      });
    // The planted java.exe in the repository (also named as a relative entry) is never used.
    expect(
      run(
        { PATH: ".;C:\\work\\repo;;C:\\jdk\\bin" },
        exists("C:\\work\\repo\\java.exe", "java.exe", "C:\\jdk\\bin\\java.exe"),
      ),
    ).toBe("C:\\jdk\\bin\\java.exe");
    expect(run({ PATH: ".;;C:\\work\\repo\\bin" }, () => true)).toBeNull();
    expect(run({ Path: "C:\\jdk\\bin" }, exists("C:\\jdk\\bin\\java.exe"))).toBe(
      "C:\\jdk\\bin\\java.exe",
    );
    expect(run({}, () => true)).toBeNull();
    // JAVA_HOME must be absolute here too.
    expect(
      run(
        { JAVA_HOME: "jdk", PATH: "" },
        exists("jdk\\bin\\java.exe", "C:\\work\\repo\\jdk\\bin\\java.exe"),
      ),
    ).toBeNull();
    expect(run({ JAVA_HOME: "C:\\jdk", PATH: "" }, exists("C:\\jdk\\bin\\java.exe"))).toBe(
      "C:\\jdk\\bin\\java.exe",
    );
  });
});

describe("readJavaVersionOutput", () => {
  it("runs the resolved absolute java with `-version`, no shell, SIGKILL, a cap and a minimal environment", async () => {
    const calls: Call[] = [];
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin", GITHUB_TOKEN: "ghp_secret", HOME: "/home/me", JAVA_HOME: "" },
      platform: "linux",
      isFile: exists("/usr/bin/java"),
      execFile: fake((cb) => cb(null, "", 'openjdk version "17.0.21"'), calls) as never,
    });
    expect(probe).toEqual({ status: "output", text: 'openjdk version "17.0.21"\n' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.file).toBe("/usr/bin/java");
    expect(calls[0]?.args).toEqual(["-version"]);
    expect(calls[0]?.options["shell"]).toBe(false);
    expect(calls[0]?.options["timeout"]).toBe(JAVA_TIMEOUT_MS);
    expect(calls[0]?.options["killSignal"]).toBe("SIGKILL");
    expect(calls[0]?.options["maxBuffer"]).toBe(JAVA_OUTPUT_CAP_BYTES);
    expect(calls[0]?.options["env"]).toEqual({ PATH: "/usr/bin", JAVA_HOME: "" });
  });

  it("does not run anything when no trusted java exists", async () => {
    const calls: Call[] = [];
    const probe = await readJavaVersionOutput({
      env: { PATH: ".:" },
      platform: "linux",
      isFile: () => true,
      execFile: fake((cb) => cb(null, "", "x"), calls) as never,
    });
    expect(probe).toEqual({ status: "missing" });
    expect(calls).toHaveLength(0);
  });

  it("reports no Java for ENOENT and for the macOS stub message", async () => {
    const base = { env: { PATH: "/usr/bin" }, platform: "linux" as const, isFile: () => true };
    const missing = await readJavaVersionOutput({
      ...base,
      execFile: fake((cb) => cb(failure("ENOENT"), "", "")) as never,
    });
    expect(missing).toEqual({ status: "missing" });
    const stub = await readJavaVersionOutput({
      ...base,
      execFile: fake((cb) =>
        cb(failure(1), "", "The operation couldn't be completed. Unable to locate a Java Runtime."),
      ) as never,
    });
    expect(stub).toEqual({ status: "missing" });
  });

  it("reports a Java that cannot be run: permission denied, timeout, other errors", async () => {
    const run = (error: Error) =>
      readJavaVersionOutput({
        env: { PATH: "/usr/bin" },
        platform: "linux",
        isFile: () => true,
        execFile: fake((cb) => cb(error, "", "")) as never,
      });
    expect(await run(failure("EACCES"))).toEqual({ status: "failed", cause: "access" });
    expect(await run(failure(null, { killed: true }))).toEqual({
      status: "failed",
      cause: "timeout",
    });
    expect(await run(failure(1))).toEqual({ status: "failed", cause: "error" });
  });

  it("still reads the version of a non-zero exit that printed it", async () => {
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin" },
      platform: "linux",
      isFile: () => true,
      execFile: fake((cb) => cb(failure(1), "", 'openjdk version "21.0.13"')) as never,
    });
    expect(probe.status).toBe("output");
  });

  it("keeps only the capped output when the child printed too much", async () => {
    const big = "x".repeat(JAVA_OUTPUT_CAP_BYTES * 3);
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin" },
      platform: "linux",
      isFile: () => true,
      execFile: fake((cb) =>
        cb(failure("ERR_CHILD_PROCESS_STDIO_MAXBUFFER", { killed: true }), "", big),
      ) as never,
    });
    expect(probe.status).toBe("output");
    if (probe.status === "output") {
      expect(probe.text.length).toBeLessThanOrEqual(JAVA_OUTPUT_CAP_BYTES);
    }
  });

  it("never throws, even when execFile itself throws", async () => {
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin" },
      platform: "linux",
      isFile: () => true,
      execFile: (() => {
        throw new Error("spawn exploded");
      }) as never,
    });
    expect(probe).toEqual({ status: "failed", cause: "error" });
  });

  it("answers 'timeout' on its own timer when the callback never fires", async () => {
    const killed: string[] = [];
    const started = Date.now();
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin" },
      platform: "win32",
      cwd: "C:\\elsewhere",
      timeoutMs: 50,
      isFile: () => true,
      // A runner that never answers (a child that ignores signals, or a held-open pipe).
      execFile: (() => ({ kill: (signal: string) => killed.push(signal) })) as never,
    });
    // PATH has no drive-absolute entry on win32, so use a fitting one.
    expect(probe.status).toBe("missing");
    const probe2 = await readJavaVersionOutput({
      env: { PATH: "C:\\jdk\\bin" },
      platform: "win32",
      cwd: "C:\\elsewhere",
      timeoutMs: 50,
      isFile: () => true,
      execFile: (() => ({ kill: (signal: string) => killed.push(signal) })) as never,
    });
    expect(probe2).toEqual({ status: "failed", cause: "timeout" });
    expect(killed).toEqual(["SIGKILL"]);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

describe.skipIf(process.platform === "win32")("a real child that ignores SIGTERM", () => {
  const scratch: string[] = [];
  afterEach(async () => {
    for (const dir of scratch.splice(0)) await rm(dir, { recursive: true, force: true });
  });

  it("is killed with its own children and reported as a timeout", async () => {
    const home = await mkdtemp(path.join(tmpdir(), "pgard-fakejava-"));
    scratch.push(home);
    await mkdir(path.join(home, "bin"));
    const script = path.join(home, "bin", "java");
    // Test-only script, not a real java: it traps TERM and keeps a grandchild alive.
    await writeFile(script, "#!/bin/sh\ntrap '' TERM\nsleep 30 &\nsleep 30\n");
    await chmod(script, 0o755);
    const started = Date.now();
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin:/bin", JAVA_HOME: home },
      timeoutMs: 300,
    });
    expect(probe).toEqual({ status: "failed", cause: "timeout" });
    expect(Date.now() - started).toBeLessThan(3000);
  });
});
