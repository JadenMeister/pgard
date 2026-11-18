import { EventEmitter } from "node:events";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  JAVA_OUTPUT_CAP_BYTES,
  JAVA_TIMEOUT_MS,
  readJavaVersionOutput,
  resolveJavaExecutable,
  type JavaChild,
  type SpawnFn,
} from "./probe.js";

interface Call {
  file: string;
  args: readonly string[];
  options: Record<string, unknown>;
}

interface FakeChild extends JavaChild {
  emitter: EventEmitter;
  out: PassThrough;
  err: PassThrough;
  signals: string[];
}

/** A fake child process: nothing is started. `script` drives it after it is "spawned". */
function fakeSpawn(script: (child: FakeChild) => void, calls: Call[] = []): SpawnFn {
  return (file, args, options) => {
    calls.push({ file, args, options });
    const emitter = new EventEmitter();
    const out = new PassThrough();
    const err = new PassThrough();
    const signals: string[] = [];
    const child: FakeChild = {
      emitter,
      out,
      err,
      signals,
      stdout: out,
      stderr: err,
      kill: (signal) => {
        signals.push(signal ?? "SIGTERM");
        return true;
      },
      once: (event, listener) => emitter.once(event, listener as never),
    };
    queueMicrotask(() => script(child));
    return child;
  };
}

const closeWith = (child: FakeChild, code: number | null) => child.emitter.emit("close", code);
const fail = (code: string) => (child: FakeChild) =>
  child.emitter.emit("error", Object.assign(new Error("boom"), { code }));

/** Only these absolute files "exist". */
const exists =
  (...files: string[]) =>
  (file: string) =>
    files.includes(file);

const LINUX = { env: { PATH: "/usr/bin" }, platform: "linux" as const, isFile: () => true };

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
  it("spawns the resolved absolute java with `-version`: no shell, no stdin, a minimal environment", async () => {
    const calls: Call[] = [];
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin", GITHUB_TOKEN: "ghp_secret", HOME: "/home/me", JAVA_HOME: "" },
      platform: "linux",
      isFile: exists("/usr/bin/java"),
      spawn: fakeSpawn((child) => {
        child.err.write('openjdk version "17.0.21"\n');
        closeWith(child, 0);
      }, calls),
    });
    expect(probe).toEqual({ status: "output", text: 'openjdk version "17.0.21"\n\n' });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.file).toBe("/usr/bin/java");
    expect(calls[0]?.args).toEqual(["-version"]);
    expect(calls[0]?.options["shell"]).toBe(false);
    expect(calls[0]?.options["stdio"]).toEqual(["ignore", "pipe", "pipe"]);
    expect(calls[0]?.options["env"]).toEqual({ PATH: "/usr/bin", JAVA_HOME: "" });
    expect(JAVA_TIMEOUT_MS).toBe(5000);
  });

  it("does not run anything when no trusted java exists", async () => {
    const calls: Call[] = [];
    const probe = await readJavaVersionOutput({
      env: { PATH: ".:" },
      platform: "linux",
      isFile: () => true,
      spawn: fakeSpawn(() => undefined, calls),
    });
    expect(probe).toEqual({ status: "missing" });
    expect(calls).toHaveLength(0);
  });

  it("reports no Java for ENOENT and for the macOS stub message", async () => {
    expect(await readJavaVersionOutput({ ...LINUX, spawn: fakeSpawn(fail("ENOENT")) })).toEqual({
      status: "missing",
    });
    const stub = await readJavaVersionOutput({
      ...LINUX,
      spawn: fakeSpawn((child) => {
        child.err.write("The operation couldn't be completed. Unable to locate a Java Runtime.");
        closeWith(child, 1);
      }),
    });
    expect(stub).toEqual({ status: "missing" });
  });

  it("reports a Java that cannot be run: permission denied, other errors, silent failure", async () => {
    expect(await readJavaVersionOutput({ ...LINUX, spawn: fakeSpawn(fail("EACCES")) })).toEqual({
      status: "failed",
      cause: "access",
    });
    expect(await readJavaVersionOutput({ ...LINUX, spawn: fakeSpawn(fail("EMFILE")) })).toEqual({
      status: "failed",
      cause: "error",
    });
    expect(
      await readJavaVersionOutput({ ...LINUX, spawn: fakeSpawn((child) => closeWith(child, 1)) }),
    ).toEqual({ status: "failed", cause: "error" });
  });

  it("still reads the version of a non-zero exit that printed it", async () => {
    const probe = await readJavaVersionOutput({
      ...LINUX,
      spawn: fakeSpawn((child) => {
        child.err.write('openjdk version "21.0.13"');
        closeWith(child, 1);
      }),
    });
    expect(probe.status).toBe("output");
  });

  it("kills the child and keeps the capped output when it prints too much", async () => {
    let seen: FakeChild | undefined;
    const probe = await readJavaVersionOutput({
      ...LINUX,
      spawn: fakeSpawn((child) => {
        seen = child;
        child.err.write("x".repeat(JAVA_OUTPUT_CAP_BYTES * 3));
      }),
    });
    expect(probe.status).toBe("output");
    if (probe.status === "output") {
      expect(probe.text.length).toBeLessThanOrEqual(JAVA_OUTPUT_CAP_BYTES);
    }
    expect(seen?.signals).toEqual(["SIGKILL"]);
  });

  it("never throws, even when spawn itself throws", async () => {
    const probe = await readJavaVersionOutput({
      ...LINUX,
      spawn: () => {
        throw new Error("spawn exploded");
      },
    });
    expect(probe).toEqual({ status: "failed", cause: "error" });
  });

  it("answers 'timeout' and sends SIGKILL (not SIGTERM) when the child never closes", async () => {
    let seen: FakeChild | undefined;
    const started = Date.now();
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin" },
      platform: "linux",
      isFile: () => true,
      timeoutMs: 50,
      spawn: fakeSpawn((child) => {
        seen = child;
      }),
    });
    expect(probe).toEqual({ status: "failed", cause: "timeout" });
    expect(seen?.signals).toEqual(["SIGKILL"]);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("kills an in-flight child when PGARD exits, and stops listening afterwards", async () => {
    const known = process.listeners("exit");
    const before = known.length;
    let seen: FakeChild | undefined;
    const pending = readJavaVersionOutput({
      ...LINUX,
      spawn: fakeSpawn((child) => {
        seen = child;
      }),
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(process.listenerCount("exit")).toBe(before + 1);
    // Call only our own listener; emitting "exit" would run every other one too.
    const ours = process.listeners("exit").find((listener) => !known.includes(listener));
    (ours as (() => void) | undefined)?.();
    expect(seen?.signals).toEqual(["SIGKILL"]);
    if (seen !== undefined) closeWith(seen, 0);
    await pending;
    expect(process.listenerCount("exit")).toBe(before);
  });
});

describe.skipIf(process.platform === "win32")("a real child process (a test-only script)", () => {
  const scratch: string[] = [];
  afterEach(async () => {
    for (const dir of scratch.splice(0)) {
      try {
        process.kill(Number((await readFile(path.join(dir, "pid"), "utf8")).trim()), "SIGKILL");
      } catch {
        // already gone
      }
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function fakeJava(body: string): Promise<string> {
    const home = await mkdtemp(path.join(tmpdir(), "pgard-fakejava-"));
    scratch.push(home);
    await mkdir(path.join(home, "bin"));
    const script = path.join(home, "bin", "java");
    await writeFile(script, `#!/bin/sh\necho $$ > "${path.join(home, "pid")}"\n${body}\n`);
    await chmod(script, 0o755);
    return home;
  }

  const gone = (pid: number): boolean => {
    try {
      process.kill(pid, 0);
      return false;
    } catch {
      return true;
    }
  };

  it("is killed after the timeout even though it ignores SIGTERM, and is gone afterwards", async () => {
    // No grandchild: a shell loop that traps TERM.
    const home = await fakeJava("trap '' TERM\nwhile :; do :; done");
    const started = Date.now();
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin:/bin", JAVA_HOME: home },
      timeoutMs: 300,
    });
    expect(probe).toEqual({ status: "failed", cause: "timeout" });
    expect(Date.now() - started).toBeLessThan(3000);
    const pid = Number((await readFile(path.join(home, "pid"), "utf8")).trim());
    for (let i = 0; i < 20 && !gone(pid); i += 1) await new Promise((r) => setTimeout(r, 25));
    expect(gone(pid)).toBe(true);
  });

  it("has no readable stdin: a `read` returns at once with end of input", async () => {
    const home = await fakeJava("read line\necho 'openjdk version \"17.0.21\"' >&2");
    const started = Date.now();
    const probe = await readJavaVersionOutput({
      env: { PATH: "/usr/bin:/bin", JAVA_HOME: home },
      timeoutMs: 2000,
    });
    expect(probe.status).toBe("output");
    if (probe.status === "output") expect(probe.text).toContain('openjdk version "17.0.21"');
    expect(Date.now() - started).toBeLessThan(1500);
  });
});
