import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  LOCAL_SESSION_URL,
  openLocalUrl,
  openSkipReason,
  planLocalOpen,
  type OpenerEnvironment,
} from "./open-local-url.js";
import { createRedirectFile, REDIRECT_FILE_NAME, type RedirectFile } from "./redirect-file.js";

/** #419. Nothing here starts a process: the spawn function is always a fake. */
const TOKEN = "abcDEF012_-xyzSecretTokenValue";
const URL_WITH_TOKEN = `http://127.0.0.1:43123/#token=${TOKEN}`;
const ROOT = "/tmp";
const DIR = "/tmp/pgard-open-AbC123";
const FILE = `${DIR}/${REDIRECT_FILE_NAME}`;
const MAC = { root: ROOT, dir: DIR, file: FILE };
const WIN_ROOT = "C:\\Users\\dev\\AppData\\Local\\Temp";
const WIN_DIR = `${WIN_ROOT}\\pgard-open-AbC123`;
const WIN_FILE = `${WIN_DIR}\\${REDIRECT_FILE_NAME}`;
const WIN = { root: WIN_ROOT, dir: WIN_DIR, file: WIN_FILE };

function environment(overrides: Partial<OpenerEnvironment> = {}): OpenerEnvironment {
  return { platform: "darwin", env: {}, isTerminal: true, isDisabled: false, ...overrides };
}

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function tmpRoot(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgard-opener-test-"));
  roots.push(root);
  return root;
}

describe("planLocalOpen: the argv is our redirect file, never the link", () => {
  it("macOS: /usr/bin/open <file>", () => {
    expect(planLocalOpen(MAC, environment())).toEqual({
      kind: "open",
      command: "/usr/bin/open",
      args: [FILE],
    });
  });

  it("Linux: xdg-open <file>, only with a display", () => {
    const linux = (env: Record<string, string>) =>
      planLocalOpen(MAC, environment({ platform: "linux", env }));
    expect(linux({ DISPLAY: ":0" })).toEqual({ kind: "open", command: "xdg-open", args: [FILE] });
    expect(linux({ WAYLAND_DISPLAY: "wayland-0" }).kind).toBe("open");
    expect(linux({})).toEqual({ kind: "skip", reason: "no_display" });
    expect(linux({ DISPLAY: "" })).toEqual({ kind: "skip", reason: "no_display" });
    expect(planLocalOpen(MAC, environment({ platform: "freebsd", env: {} })).kind).toBe("skip");
  });

  it("Windows: rundll32 url.dll,FileProtocolHandler <file> by absolute path", () => {
    const plan = planLocalOpen(
      WIN,
      environment({ platform: "win32", env: { SystemRoot: "D:\\Windows" } }),
    );
    expect(plan).toEqual({
      kind: "open",
      command: "D:\\Windows\\System32\\rundll32.exe",
      args: ["url.dll,FileProtocolHandler", WIN_FILE],
    });
    const untrusted = planLocalOpen(
      WIN,
      environment({ platform: "win32", env: { SystemRoot: "\\\\evil\\share" } }),
    );
    expect(untrusted.kind === "open" && untrusted.command).toBe(
      "C:\\Windows\\System32\\rundll32.exe",
    );
  });

  it("Windows: a Korean user name or spaces are fine, and the path stays one argv element", () => {
    for (const root of [
      "C:\\Users\\홍길동\\AppData\\Local\\Temp",
      "C:\\Users\\Jane Doe\\AppData\\Local\\Temp",
      "C:\\Users\\José Müller\\AppData\\Local\\Temp",
    ]) {
      const dir = `${root}\\pgard-open-Xy9Z01`;
      const file = `${dir}\\${REDIRECT_FILE_NAME}`;
      const plan = planLocalOpen({ root, dir, file }, environment({ platform: "win32" }));
      expect(plan).toEqual({
        kind: "open",
        command: "C:\\Windows\\System32\\rundll32.exe",
        args: ["url.dll,FileProtocolHandler", file],
      });
      expect(plan.kind === "open" && plan.args).toHaveLength(2);
    }
  });

  it("refuses any argv that is not exactly our file in our own folder in our root", () => {
    const bad: Array<{ root: string; dir: string; file: string }> = [
      { root: ROOT, dir: DIR, file: URL_WITH_TOKEN },
      { root: ROOT, dir: DIR, file: "/tmp/pgard-open-AbC123/other.html" },
      { root: ROOT, dir: DIR, file: "/tmp/elsewhere/open-pgard.html" },
      { root: ROOT, dir: DIR, file: "/tmp/pgard-open-AbC123/../x/open-pgard.html" },
      { root: "tmp", dir: "tmp/pgard-open-AbC123", file: "tmp/pgard-open-AbC123/open-pgard.html" },
      { root: ROOT, dir: "/tmp/evil", file: "/tmp/evil/open-pgard.html" },
      // Not directly in our root.
      { root: "/var/other", dir: DIR, file: FILE },
      {
        root: ROOT,
        dir: "/tmp/x/pgard-open-AbC123",
        file: "/tmp/x/pgard-open-AbC123/open-pgard.html",
      },
      // Not the leaf mkdtemp makes.
      { root: ROOT, dir: "/tmp/pgard-open-", file: "/tmp/pgard-open-/open-pgard.html" },
      {
        root: ROOT,
        dir: "/tmp/pgard-open-AbC12345",
        file: "/tmp/pgard-open-AbC12345/open-pgard.html",
      },
      {
        root: '/tmp/a"&calc',
        dir: '/tmp/a"&calc/pgard-open-AbC123',
        file: '/tmp/a"&calc/pgard-open-AbC123/open-pgard.html',
      },
      {
        root: "/tmp/a\n",
        dir: "/tmp/a\n/pgard-open-AbC123",
        file: "/tmp/a\n/pgard-open-AbC123/open-pgard.html",
      },
    ];
    for (const redirect of bad) {
      for (const platform of ["darwin", "linux"] as const) {
        expect(planLocalOpen(redirect, environment({ platform, env: { DISPLAY: ":0" } }))).toEqual({
          kind: "skip",
          reason: "bad_url",
        });
      }
    }
    for (const root of [`${WIN_ROOT}\\x^&whoami`, `${WIN_ROOT}\\a%PATH%`, `${WIN_ROOT}\\a"b`]) {
      const dir = `${root}\\pgard-open-AbC123`;
      expect(
        planLocalOpen(
          { root, dir, file: `${dir}\\${REDIRECT_FILE_NAME}` },
          environment({ platform: "win32" }),
        ),
      ).toEqual({ kind: "skip", reason: "bad_url" });
    }
  });
});

describe("openSkipReason", () => {
  it("does not open with --no-open, without a terminal, in CI, or over SSH on any OS", () => {
    expect(openSkipReason(environment({ isDisabled: true }))).toBe("disabled");
    expect(openSkipReason(environment({ isTerminal: false }))).toBe("no_terminal");
    expect(openSkipReason(environment({ env: { CI: "true" } }))).toBe("ci");
    for (const platform of ["darwin", "win32", "linux"] as const) {
      for (const env of [
        { SSH_CONNECTION: "10.0.0.2 5000 10.0.0.1 22", DISPLAY: ":0" },
        { SSH_TTY: "/dev/ttys001", WAYLAND_DISPLAY: "w" },
      ]) {
        expect(openSkipReason(environment({ platform, env }))).toBe("ssh");
      }
    }
    expect(openSkipReason(environment())).toBeNull();
  });
});

describe("openLocalUrl", () => {
  it("passes no token in the argv on any OS: only the redirect file's path", async () => {
    for (const platform of ["darwin", "linux", "win32"] as const) {
      const root = tmpRoot();
      const spawn = vi.fn(async () => true);
      const { outcome, redirect } = await openLocalUrl(
        URL_WITH_TOKEN,
        environment({ platform, env: { DISPLAY: ":0" } }),
        {
          spawn,
          createRedirect: (url) => createRedirectFile(url, { tmpRoot: root }),
        },
      );
      if ((platform === "win32") !== (process.platform === "win32")) {
        // A temp path of the other path family is refused, and the file is deleted again.
        expect(outcome).toEqual({ isOpened: false, reason: "bad_url" });
        expect(spawn).not.toHaveBeenCalled();
        continue;
      }
      expect(outcome).toEqual({ isOpened: true });
      const argv = (spawn.mock.calls[0] as unknown as [string, string[]])[1];
      expect(argv.join(" ")).not.toContain(TOKEN);
      expect(argv.join(" ")).not.toContain("127.0.0.1");
      expect(argv.at(-1)).toBe(redirect?.file);
      await redirect?.remove();
    }
  });

  it("refuses a link that is not PGARD's own, and writes nothing then", async () => {
    const createRedirect = vi.fn();
    for (const url of [
      "http://127.0.0.1:43123/#token=abc&calc.exe",
      "http://localhost:43123/#token=abc",
      "http://127.0.0.1:43123/",
      "file:///C:/Windows/System32/calc.exe",
    ]) {
      const { outcome } = await openLocalUrl(url, environment(), { createRedirect });
      expect(outcome).toEqual({ isOpened: false, reason: "bad_url" });
    }
    expect(createRedirect).not.toHaveBeenCalled();
    expect(LOCAL_SESSION_URL.test(URL_WITH_TOKEN)).toBe(true);
  });

  it("writes no file when it will not open, and deletes it when the opener fails", async () => {
    const createRedirect = vi.fn();
    await openLocalUrl(URL_WITH_TOKEN, environment({ isTerminal: false }), { createRedirect });
    expect(createRedirect).not.toHaveBeenCalled();

    const root = tmpRoot();
    let made: RedirectFile | null = null;
    const host = environment({ platform: process.platform === "win32" ? "win32" : "darwin" });
    const failing = await openLocalUrl(URL_WITH_TOKEN, host, {
      spawn: async () => false,
      createRedirect: async (url) => (made = await createRedirectFile(url, { tmpRoot: root })),
    });
    expect(failing).toEqual({ outcome: { isOpened: false, reason: "failed" }, redirect: null });
    const { existsSync } = await import("node:fs");
    expect(existsSync((made as RedirectFile | null)?.dir ?? "")).toBe(false);

    const throwing = await openLocalUrl(URL_WITH_TOKEN, environment(), {
      spawn: () => Promise.reject(new Error("boom")),
      createRedirect: (url) => createRedirectFile(url, { tmpRoot: root }),
    });
    expect(throwing.outcome.isOpened).toBe(false);
    const unwritable = await openLocalUrl(URL_WITH_TOKEN, environment(), {
      createRedirect: () => Promise.reject(new Error("disk full")),
    });
    expect(unwritable.outcome).toEqual({ isOpened: false, reason: "failed" });
  });

  it("spawns with shell: false and an argv array, and waits for the exit code", async () => {
    const source = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL("./open-local-url.ts", import.meta.url), "utf8"),
    );
    expect(source).toContain("shell: false");
    expect(source).toContain('child.once("exit"');
    expect(source).not.toMatch(/exec\(|execSync|shell: true/);
  });
});

describe.skipIf(process.platform === "win32")("spawnDetached (no browser: true and false)", () => {
  it("treats a non-zero exit within the grace period as a failure", async () => {
    const { spawnDetached } = await import("./open-local-url.js");
    expect(await spawnDetached("false", [])).toBe(false);
    expect(await spawnDetached("true", [])).toBe(true);
    expect(await spawnDetached("/nonexistent/opener", [])).toBe(false);
  });
});
