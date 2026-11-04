import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import {
  nodeScopeFs,
  windowsSystemFolders,
  type ScopeFs,
  type ScopeStat,
} from "@pgard/result-store";
import { afterEach, describe, expect, it } from "vitest";
import { absolutePathOf, shortenHome } from "./candidates.js";
import { expandPastedPath } from "./choose-folder.js";
import {
  createFolderDialog,
  decodeWindowsDialogOutput,
  dialogCommandFor,
  WINDOWS_DIALOG_SCRIPT,
  windowsPowerShellPath,
} from "./folder-dialog.js";
import { inspectCandidate, runInspectorJob } from "./inspect.js";
import { createInspectorHost, inspectorEnvironment, taskkillPath } from "./inspector-host.js";
import type { ChildMessage, InspectorJob } from "./protocol.js";
import { createInspectorDeps } from "./test-support/fixtures.js";
import { validateChildMessage } from "./validate-message.js";

/**
 * #477: `pgard web` on Windows. Most of this runs on every OS with an injected platform and a
 * virtual Windows file system; the last block uses real paths and runs on Windows only.
 */

const HOME = "C:\\Users\\김철수";
const SYSTEM = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData"];

const directory = (ino: number): ScopeStat => ({
  isDirectory: true,
  isFile: false,
  isSymbolicLink: false,
  uid: 0,
  mode: 0o40777,
  dev: 3,
  ino,
});

/** A virtual Windows volume: case-insensitive, with `realpath` aliases (junctions, drives). */
function virtualWindowsFs(folders: string[], aliases: Record<string, string> = {}): ScopeFs {
  const canonical = new Map(folders.map((entry) => [entry.toLowerCase(), entry]));
  const links = new Map(Object.entries(aliases).map(([from, to]) => [from.toLowerCase(), to]));
  const gone = (): Error => Object.assign(new Error("not found"), { code: "ENOENT" });
  const inodes = new Map(folders.map((entry, index) => [entry.toLowerCase(), index + 10]));
  return {
    async lstat(target) {
      const ino = inodes.get(target.toLowerCase());
      if (ino === undefined) throw gone();
      return directory(ino);
    },
    async realpath(target) {
      const linked = links.get(target.toLowerCase());
      if (linked !== undefined) return linked;
      const found = canonical.get(target.toLowerCase());
      if (found === undefined) throw gone();
      return found;
    },
    async readdir() {
      return [];
    },
  };
}

const FOLDERS = [
  "C:\\",
  "C:\\Users",
  HOME,
  `${HOME}\\code`,
  `${HOME}\\code\\app`,
  `${HOME}\\code\\프로젝트 앱`,
  "C:\\Windows",
  "C:\\Windows\\System32",
  "C:\\Program Files",
  "C:\\Program Files\\Tool",
  "D:\\",
  "D:\\work",
  "D:\\work\\app",
];

async function resolveOnWindows(
  target: string,
  aliases: Record<string, string> = {},
): Promise<ChildMessage[]> {
  const { deps, messages } = createInspectorDeps({
    platform: "win32",
    uid: undefined,
    fs: virtualWindowsFs(FOLDERS, aliases),
  });
  const job: InspectorJob = {
    kind: "resolve",
    path: target,
    homeDir: HOME,
    systemFolders: SYSTEM,
  };
  await runInspectorJob(deps, job);
  for (const message of messages) {
    expect(validateChildMessage(message, job)).not.toBeNull();
  }
  return messages;
}

const refusalOf = (messages: ChildMessage[]): string | undefined => {
  const refused = messages.find((message) => message.t === "refused");
  return refused?.t === "refused" ? refused.reason : undefined;
};

describe("resolve job with a Windows platform (virtual volume)", () => {
  it("resolves a folder in the profile like a search candidate, from the profile as anchor", async () => {
    const messages = await resolveOnWindows(`${HOME}\\code\\app`);
    const resolved = messages.find((message) => message.t === "resolved");
    expect(resolved?.t === "resolved" && resolved.root.path).toBe(HOME);
    expect(resolved?.t === "resolved" && resolved.candidate.segments.map((s) => s.name)).toEqual([
      "code",
      "app",
    ]);
    // No `.git`: blocked as a candidate, but a valid folder.
    expect(resolved?.t === "resolved" && resolved.candidate.block?.code).toBe("not_a_git_root");
    expect(resolved?.t === "resolved" && resolved.folderBlock).toBeNull();
  });

  it("resolves a Korean folder name and compares case-insensitively through realpath", async () => {
    const lower = `${HOME}\\CODE\\프로젝트 앱`.toLowerCase().replace("c:\\users", "C:\\Users");
    const messages = await resolveOnWindows(lower);
    const resolved = messages.find((message) => message.t === "resolved");
    expect(resolved?.t === "resolved" && resolved.candidate.segments.map((s) => s.name)).toEqual([
      "code",
      "프로젝트 앱",
    ]);
  });

  it("resolves a folder outside the profile, from the folder itself", async () => {
    const resolved = (await resolveOnWindows("D:\\work\\app")).find(
      (message) => message.t === "resolved",
    );
    expect(resolved?.t === "resolved" && resolved.root.path).toBe("D:\\work\\app");
  });

  it.each([
    ["a UNC path", "\\\\server\\share\\code"],
    ["a UNC path with slashes", "//server/share/code"],
    ["a device path", "\\\\?\\C:\\Users\\김철수\\code"],
    ["a device path with dots", "\\\\.\\C:\\Users\\김철수\\code"],
    ["a slash device path", "//?/C:/Users/김철수/code"],
    ["a drive-relative path", "C:code"],
    ["a drive-relative root", "C:"],
    ["a rooted path without a drive", "\\code"],
    ["an alternate data stream", `${HOME}\\code:stream`],
    ["a trailing dot", `${HOME}\\code\\app.`],
    ["a trailing space", `${HOME}\\code\\app `],
    ["a reserved name", `${HOME}\\code\\NUL`],
    ["a path that is not normalized", `${HOME}\\code\\..\\code\\app`],
    ["forward slashes", `C:/Users/김철수/code/app`],
  ])("refuses %s as a bad path", async (_label, target) => {
    expect(refusalOf(await resolveOnWindows(target))).toBe("bad_path");
  });

  it("refuses drive roots, top-level folders and the profile folder or its parents as too broad", async () => {
    for (const target of ["C:\\", "D:\\", "c:\\", "C:\\Users", "D:\\work", HOME]) {
      expect(refusalOf(await resolveOnWindows(target))).toBe("too_broad");
    }
    // The profile in another spelling.
    expect(refusalOf(await resolveOnWindows(HOME.toUpperCase()))).toBe("too_broad");
  });

  it("refuses the operating system and program folders", async () => {
    for (const target of [
      "C:\\Windows\\System32",
      "C:\\Program Files\\Tool",
      "c:\\windows\\system32",
    ]) {
      expect(refusalOf(await resolveOnWindows(target))).toBe("too_broad");
    }
  });

  it("resolves junctions and links before any check: a link to a share, a drive root or the system is refused", async () => {
    const aliases = {
      [`${HOME}\\code\\to-share`]: "\\\\server\\share\\app",
      [`${HOME}\\code\\to-root`]: "C:\\",
      [`${HOME}\\code\\to-system`]: "C:\\Windows\\System32",
      [`${HOME}\\code\\to-device`]: "\\\\?\\GLOBALROOT\\Device\\x",
      [`${HOME}\\code\\to-home`]: HOME,
    };
    const virtual = [
      ...FOLDERS,
      `${HOME}\\code\\to-share`,
      `${HOME}\\code\\to-root`,
      `${HOME}\\code\\to-system`,
      `${HOME}\\code\\to-device`,
      `${HOME}\\code\\to-home`,
    ];
    const run = async (name: string): Promise<string | undefined> => {
      const { deps, messages } = createInspectorDeps({
        platform: "win32",
        uid: undefined,
        fs: virtualWindowsFs(virtual, aliases),
      });
      await runInspectorJob(deps, {
        kind: "resolve",
        path: `${HOME}\\code\\${name}`,
        homeDir: HOME,
        systemFolders: SYSTEM,
      });
      return refusalOf(messages);
    };
    expect(await run("to-share")).toBe("bad_path");
    expect(await run("to-device")).toBe("bad_path");
    expect(await run("to-root")).toBe("too_broad");
    expect(await run("to-system")).toBe("too_broad");
    expect(await run("to-home")).toBe("too_broad");
  });
});

describe("pasted paths on Windows", () => {
  const expand = (raw: unknown) => expandPastedPath(raw, HOME, "win32");

  it("accepts plain local paths, normalizing separators and the trailing one", () => {
    expect(expand("C:\\Users\\김철수\\code\\app")).toBe("C:\\Users\\김철수\\code\\app");
    expect(expand("C:/Users/김철수/code/app/")).toBe("C:\\Users\\김철수\\code\\app");
    expect(expand("  D:\\work\\app  ")).toBe("D:\\work\\app");
    expect(expand('"D:\\work\\my app"')).toBe("D:\\work\\my app");
  });

  it("expands ~ to the profile folder with either separator", () => {
    expect(expand("~")).toBe(HOME);
    expect(expand("~\\code")).toBe(`${HOME}\\code`);
    expect(expand("~/code/app")).toBe(`${HOME}\\code\\app`);
    expect(expand("~other\\x")).toBeNull();
  });

  it.each([
    "\\\\server\\share\\code",
    "//server/share/code",
    "\\\\?\\C:\\code",
    "\\\\.\\C:\\code",
    "//?/C:/code",
    "C:code",
    "\\code",
    "/code",
    "code\\app",
    "C:\\code\\app:stream",
    "C:\\code\\app.",
    "C:\\code\\app. ",
    "C:\\code\\sub \\app",
    "C:\\code\\COM1",
    "C:\\a\u0000b",
    "C:\\code\\a|b",
    "",
    42,
  ])("refuses %j", (raw) => {
    expect(expand(raw)).toBeNull();
  });

  it("keeps the POSIX rules when the platform is not Windows", () => {
    expect(expandPastedPath("C:\\code", "/home/u", "linux")).toBeNull();
    expect(expandPastedPath("/home/u/code", "/home/u", "linux")).toBe("/home/u/code");
  });
});

describe("Windows paths in the candidate view", () => {
  it("shortens the profile folder case-insensitively and keeps backslashes", () => {
    expect(shortenHome(`${HOME}\\code\\app`, HOME)).toBe("~\\code\\app");
    expect(shortenHome(HOME.toLowerCase(), HOME)).toBe("~");
    expect(shortenHome(`${HOME.toLowerCase()}\\x`, HOME)).toBe("~\\x");
    expect(shortenHome("D:\\work", HOME)).toBe("D:\\work");
    expect(shortenHome("/home/u/code", "/home/u")).toBe("~/code");
  });

  it("joins a chain with backslashes", () => {
    expect(
      absolutePathOf({ path: HOME, dev: 1, ino: 2 }, [
        { name: "code", dev: 1, ino: 3 },
        { name: "app", dev: 1, ino: 4 },
      ]),
    ).toBe(`${HOME}\\code\\app`);
  });
});

describe("the Windows folder dialog command", () => {
  const env = { SystemRoot: "C:\\Windows" };
  const prompt = '검사할 "프로젝트" 폴더 $(calc) `x`; & | > <';

  it("runs Windows PowerShell by absolute path with the fixed flags and script", async () => {
    const command = await dialogCommandFor("win32", prompt, async () => true, env);
    expect(command?.file).toBe("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    expect(command?.args.slice(0, 4)).toEqual([
      "-NoProfile",
      "-NonInteractive",
      "-STA",
      "-EncodedCommand",
    ]);
    expect(command?.args).toHaveLength(5);
    const script = Buffer.from(command?.args[4] ?? "", "base64").toString("utf16le");
    expect(script).toBe(WINDOWS_DIALOG_SCRIPT);
    expect(command?.cancelCodes).toEqual([3]);
  });

  it("passes the prompt only through the environment, never in the arguments or the script", async () => {
    const first = await dialogCommandFor("win32", prompt, async () => true, env);
    const second = await dialogCommandFor("win32", "something else", async () => true, env);
    expect(first?.env).toEqual({ PGARD_DIALOG_PROMPT: prompt });
    expect(first?.args.join(" ")).not.toContain("calc");
    expect(WINDOWS_DIALOG_SCRIPT).not.toContain("calc");
    expect(WINDOWS_DIALOG_SCRIPT).toContain("$env:PGARD_DIALOG_PROMPT");
    // The arguments (and so the script) are the same whatever the prompt is.
    expect(second?.args).toEqual(first?.args);
  });

  it("trusts SystemRoot only as a plain drive path", async () => {
    for (const bad of [
      "\\\\evil\\share",
      "C:\\Windows\\..\\Temp",
      "",
      "relative",
      "\\\\?\\C:\\Windows",
    ]) {
      expect(windowsPowerShellPath({ SystemRoot: bad })).toBe(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      );
    }
    expect(windowsPowerShellPath({ SystemRoot: "D:\\WINNT" })).toBe(
      "D:\\WINNT\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
    expect(windowsPowerShellPath({ SYSTEMROOT: "E:\\Windows" })).toBe(
      "E:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
  });

  it("is unavailable when PowerShell is missing", async () => {
    expect(await dialogCommandFor("win32", "p", async () => false, env)).toBeNull();
    const dialog = createFolderDialog({
      platform: "win32",
      env,
      isExecutable: async () => false,
      run: async () => {
        throw new Error("must not run");
      },
    });
    expect(await dialog({ prompt: "p", signal: new AbortController().signal })).toEqual({
      status: "unavailable",
    });
  });

  it("decodes a Korean folder name from the UTF-8 base64 output", () => {
    const encode = (text: string): string => Buffer.from(text, "utf8").toString("base64");
    expect(decodeWindowsDialogOutput(encode("C:\\Users\\김철수\\프로젝트"))).toBe(
      "C:\\Users\\김철수\\프로젝트",
    );
    expect(decodeWindowsDialogOutput(`${encode("D:\\work")}\r\n`)).toBe("D:\\work");
    expect(decodeWindowsDialogOutput("")).toBe("");
    expect(decodeWindowsDialogOutput("not base64!")).toBeNull();
    // Bytes that are not UTF-8.
    expect(
      decodeWindowsDialogOutput(Buffer.from([0xff, 0xfe, 0x41]).toString("base64")),
    ).toBeNull();
  });

  it("maps the exit codes: chosen, cancelled (3), a failing script or a missing tool", async () => {
    const signal = new AbortController().signal;
    const run = (code: number | null, stdout = "", timedOut = false) =>
      createFolderDialog({
        platform: "win32",
        env,
        isExecutable: async () => true,
        run: async () => ({ code, stdout, timedOut }),
      })({ prompt: "p", signal });
    const output = Buffer.from("C:\\Users\\김철수\\code", "utf8").toString("base64");
    expect(await run(0, output)).toEqual({ status: "chosen", path: "C:\\Users\\김철수\\code" });
    expect(await run(3)).toEqual({ status: "cancelled" });
    expect(await run(0, "")).toEqual({ status: "cancelled" });
    // 1: the script failed (a blocked assembly, a policy, no desktop); null: no such file.
    expect(await run(1)).toEqual({ status: "unavailable" });
    expect(await run(null)).toEqual({ status: "unavailable" });
    expect(await run(0, "###")).toEqual({ status: "unavailable" });
    expect(await run(null, "", true)).toEqual({ status: "timeout" });
  });
});

describe("the macOS and Linux dialog commands keep working", () => {
  it("still builds osascript and zenity commands without an environment or encoding", async () => {
    const mac = await dialogCommandFor("darwin", "p");
    expect(mac?.env).toBeUndefined();
    expect(mac?.output).toBeUndefined();
    const linux = await dialogCommandFor("linux", "p", async (file) => file.endsWith("zenity"));
    expect(linux?.file).toMatch(/zenity$/);
  });
});

let base: string | undefined;
afterEach(() => {
  if (base !== undefined) rmSync(base, { recursive: true, force: true });
  base = undefined;
});

/** Real paths: Windows only (junctions, drive roots, real `realpath`). */
describe.skipIf(process.platform !== "win32")("resolve job on a real Windows volume", () => {
  const realHome = (): string => realpathSync.native(process.env.USERPROFILE ?? homedir());

  async function resolveReal(target: string): Promise<ChildMessage[]> {
    const { deps, messages } = createInspectorDeps({
      platform: "win32",
      uid: undefined,
      fs: nodeScopeFs,
    });
    await runInspectorJob(deps, {
      kind: "resolve",
      path: target,
      homeDir: realHome(),
      systemFolders: windowsSystemFolders(process.env),
    });
    return messages;
  }

  it("resolves a folder, refuses the drive root and the profile, and follows a junction", async () => {
    base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-win-")));
    const project = path.join(base, "project");
    mkdirSync(project);
    const resolved = (await resolveReal(project)).find((message) => message.t === "resolved");
    expect(resolved?.t === "resolved" && resolved.candidate.segments.at(-1)?.name).toBe("project");

    expect(refusalOf(await resolveReal(path.parse(project).root))).toBe("too_broad");
    expect(refusalOf(await resolveReal(realHome()))).toBe("too_broad");
    expect(refusalOf(await resolveReal(`\\\\?\\${project}`))).toBe("bad_path");
    expect(refusalOf(await resolveReal(`${project}:stream`))).toBe("bad_path");

    // A junction is resolved to its target before the checks: a junction to the drive root is
    // refused as the drive root, one to a project is that project.
    const toRoot = path.join(base, "to-root");
    symlinkSync(path.parse(project).root, toRoot, "junction");
    expect(refusalOf(await resolveReal(toRoot))).toBe("too_broad");
    const toProject = path.join(base, "to-project");
    symlinkSync(project, toProject, "junction");
    const viaJunction = (await resolveReal(toProject)).find((message) => message.t === "resolved");
    expect(viaJunction?.t === "resolved" && viaJunction.candidate.segments.at(-1)?.name).toBe(
      "project",
    );
    // Different letter case is the same folder.
    const swapped = (await resolveReal(project.toUpperCase())).find(
      (message) => message.t === "resolved",
    );
    expect(swapped?.t).toBe("resolved");
  });

  it("refuses a link to an administrative share and a short (8.3) name in a system folder", async () => {
    base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-win-")));
    const link = path.join(base, "to-share");
    let isLinked = true;
    try {
      symlinkSync("\\\\localhost\\C$\\Windows", link, "dir");
    } catch {
      isLinked = false; // creating links needs a privilege the runner has and a developer may not
    }
    if (isLinked) expect(refusalOf(await resolveReal(link))).toBe("bad_path");
    const short = "C:\\PROGRA~1\\Common Files";
    if (existsSync(short)) expect(refusalOf(await resolveReal(short))).toBe("too_broad");
  });

  it("refuses the Windows folder itself", async () => {
    const windir = process.env.SystemRoot ?? "C:\\Windows";
    expect(refusalOf(await resolveReal(path.join(windir, "System32")))).toBe("too_broad");
  });
});

describe("ids beyond 2^53 (NTFS file ids)", () => {
  const BIG = "18446744073709551615";

  it("the child message validation accepts decimal strings and refuses an unsafe number", () => {
    const job: InspectorJob = { kind: "resolve", path: `${HOME}\\code`, homeDir: HOME };
    const message = (ino: unknown) => ({
      t: "resolved",
      root: { path: HOME, dev: "7", ino },
      candidate: {
        rootIndex: 0,
        segments: [{ name: "code", dev: "7", ino: BIG }],
        gitIdentity: null,
        remote: { status: "unreadable" },
        block: { code: "not_a_git_root", paths: [] },
      },
      folderBlock: null,
    });
    expect(validateChildMessage(message(BIG), job)).not.toBeNull();
    expect(validateChildMessage(message(2 ** 53 + 2), job)).toBeNull();
    expect(validateChildMessage(message("1e5"), job)).toBeNull();
    expect(validateChildMessage(message("1".repeat(21)), job)).toBeNull();
    expect(validateChildMessage(message("-1"), job)).toBeNull();
  });

  it("two ids that differ only beyond 2^53 are different folders", async () => {
    const fs: ScopeFs = {
      async lstat() {
        return { ...directory(0), dev: "7", ino: "9007199254740993" };
      },
      async realpath(target) {
        return target;
      },
      async readdir() {
        return [];
      },
    };
    const { deps } = createInspectorDeps({ platform: "win32", uid: undefined, fs });
    const same = { path: HOME, dev: "7", ino: "9007199254740993" };
    const other = { path: HOME, dev: "7", ino: "9007199254740992" };
    await expect(inspectCandidate(deps, same, 0, [], "recheck")).resolves.toBeDefined();
    await expect(inspectCandidate(deps, other, 0, [], "recheck")).rejects.toThrow();
  });
});

describe("the inspector child environment and process tree", () => {
  it("passes a validated SystemRoot on Windows, never the whole environment", () => {
    const env = inspectorEnvironment(
      {
        SystemRoot: "D:\\WINNT",
        PATH: "D:\\bin",
        TEMP: "D:\\tmp",
        GITHUB_TOKEN: "secret",
        PGARD_X: "1",
        ProgramFiles: "D:\\Programs",
      },
      "win32",
    );
    expect(env.SystemRoot).toBe("D:\\WINNT");
    expect(env.windir).toBe("D:\\WINNT");
    expect(env.TEMP).toBe("D:\\tmp");
    expect(Object.keys(env).sort()).toEqual(
      ["NoDefaultCurrentDirectoryInExePath", "PATH", "SystemRoot", "TEMP", "windir"].sort(),
    );
    expect(inspectorEnvironment({ SystemRoot: "\\\\evil\\share" }, "win32").SystemRoot).toBe(
      "C:\\Windows",
    );
    expect(inspectorEnvironment({ SystemRoot: "C:\\a\\..\\b" }, "win32").SystemRoot).toBe(
      "C:\\Windows",
    );
    expect(inspectorEnvironment({ SystemRoot: "D:\\WINNT" }, "linux").SystemRoot).toBeUndefined();
  });

  it("starts taskkill from the absolute system folder", () => {
    expect(taskkillPath({ SystemRoot: "D:\\WINNT" })).toBe("D:\\WINNT\\System32\\taskkill.exe");
    expect(taskkillPath({ SystemRoot: "\\\\evil\\x" })).toBe("C:\\Windows\\System32\\taskkill.exe");
  });

  /** A child that starts a long-lived grandchild and writes its pid where the job says. */
  function grandchildScript(directory: string): string {
    const script = path.join(directory, "child.mjs");
    writeFileSync(
      script,
      [
        'import { spawn } from "node:child_process";',
        'import { writeFileSync } from "node:fs";',
        'process.once("message", (job) => {',
        '  const gc = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });',
        "  writeFileSync(job.path, String(gc.pid));",
        "});",
        "setInterval(() => {}, 1000);",
      ].join("\n"),
    );
    return script;
  }

  const isAlive = (pid: number): boolean => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };

  it("kills the child's whole process tree on cancel", async () => {
    base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-tree-")));
    const pidFile = path.join(base, "grandchild.pid");
    const host = createInspectorHost({
      entry: grandchildScript(base),
      env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
    });
    const running = host.run(
      { kind: "resolve", path: pidFile, homeDir: base },
      { hardMs: 60_000, onMessage: () => undefined },
    );
    expect(running).not.toBeNull();
    const deadline = Date.now() + 20_000;
    while (!existsSync(pidFile) || readFileSync(pidFile, "utf8") === "") {
      if (Date.now() > deadline) throw new Error("the grandchild did not start");
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const grandchild = Number(readFileSync(pidFile, "utf8"));
    expect(isAlive(grandchild)).toBe(true);
    running?.cancel();
    await running?.result;
    const gone = Date.now() + 20_000;
    while (isAlive(grandchild) && Date.now() < gone) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(isAlive(grandchild)).toBe(false);
    host.stopAll();
  }, 60_000);
});

/** The real inspector child, end to end, on Windows (needs the built `dist`, as CI has). */
describe.skipIf(process.platform !== "win32")("the real inspector child on Windows", () => {
  it("resolves a folder and refuses a share path through the host", async () => {
    base = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-host-")));
    const project = path.join(base, "project");
    mkdirSync(project);
    const host = createInspectorHost();
    const run = async (target: string): Promise<ChildMessage[]> => {
      const messages: ChildMessage[] = [];
      const running = host.run(
        {
          kind: "resolve",
          path: target,
          homeDir: realpathSync.native(process.env.USERPROFILE ?? homedir()),
          systemFolders: windowsSystemFolders(process.env),
        },
        { hardMs: 30_000, onMessage: (message) => messages.push(message) },
      );
      expect(running).not.toBeNull();
      expect((await running?.result)?.status).toBe("finished");
      return messages;
    };
    const resolved = (await run(project)).find((message) => message.t === "resolved");
    expect(resolved?.t === "resolved" && resolved.candidate.segments.at(-1)?.name).toBe("project");
    expect(refusalOf(await run("\\\\localhost\\C$\\Windows"))).toBe("bad_path");
    host.stopAll();
  }, 60_000);
});
