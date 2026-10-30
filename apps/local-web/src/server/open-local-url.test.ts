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
const DIR = "/tmp/pgard-open-AbC123";
const FILE = `${DIR}/${REDIRECT_FILE_NAME}`;
const WIN_DIR = "C:\\Users\\dev\\AppData\\Local\\Temp\\pgard-open-AbC123";
const WIN_FILE = `${WIN_DIR}\\${REDIRECT_FILE_NAME}`;

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
    expect(planLocalOpen(FILE, DIR, environment())).toEqual({
      kind: "open",
      command: "/usr/bin/open",
      args: [FILE],
    });
  });

  it("Linux: xdg-open <file>, only with a display", () => {
    const linux = (env: Record<string, string>) =>
      planLocalOpen(FILE, DIR, environment({ platform: "linux", env }));
    expect(linux({ DISPLAY: ":0" })).toEqual({ kind: "open", command: "xdg-open", args: [FILE] });
    expect(linux({ WAYLAND_DISPLAY: "wayland-0" }).kind).toBe("open");
    expect(linux({})).toEqual({ kind: "skip", reason: "no_display" });
    expect(linux({ DISPLAY: "" })).toEqual({ kind: "skip", reason: "no_display" });
    expect(planLocalOpen(FILE, DIR, environment({ platform: "freebsd", env: {} })).kind).toBe(
      "skip",
    );
  });

  it("Windows: rundll32 url.dll,FileProtocolHandler <file> by absolute path", () => {
    const plan = planLocalOpen(
      WIN_FILE,
      WIN_DIR,
      environment({ platform: "win32", env: { SystemRoot: "D:\\Windows" } }),
    );
    expect(plan).toEqual({
      kind: "open",
      command: "D:\\Windows\\System32\\rundll32.exe",
      args: ["url.dll,FileProtocolHandler", WIN_FILE],
    });
    const untrusted = planLocalOpen(
      WIN_FILE,
      WIN_DIR,
      environment({ platform: "win32", env: { SystemRoot: "\\\\evil\\share" } }),
    );
    expect(untrusted.kind === "open" && untrusted.command).toBe(
      "C:\\Windows\\System32\\rundll32.exe",
    );
  });

  it("refuses any argv that is not exactly our file in our own directory", () => {
    const bad: Array<[string, string]> = [
      [URL_WITH_TOKEN, DIR],
      ["/tmp/pgard-open-AbC123/other.html", DIR],
      ["/tmp/elsewhere/open-pgard.html", DIR],
      ["/tmp/pgard-open-AbC123/../x/open-pgard.html", DIR],
      ["tmp/pgard-open-AbC123/open-pgard.html", "tmp/pgard-open-AbC123"],
      ["/tmp/evil/open-pgard.html", "/tmp/evil"],
      ['/tmp/pgard-open-A"&calc/open-pgard.html', '/tmp/pgard-open-A"&calc'],
      ["/tmp/pgard-open-A\n/open-pgard.html", "/tmp/pgard-open-A\n"],
    ];
    for (const [file, dir] of bad) {
      for (const platform of ["darwin", "linux"] as const) {
        expect(planLocalOpen(file, dir, environment({ platform, env: { DISPLAY: ":0" } }))).toEqual(
          { kind: "skip", reason: "bad_url" },
        );
      }
    }
    expect(
      planLocalOpen(
        `${WIN_DIR}\\x^&whoami\\${REDIRECT_FILE_NAME}`,
        `${WIN_DIR}\\x^&whoami`,
        environment({ platform: "win32" }),
      ),
    ).toEqual({ kind: "skip", reason: "bad_url" });
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
