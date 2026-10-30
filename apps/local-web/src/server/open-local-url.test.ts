import { describe, expect, it, vi } from "vitest";
import {
  LOCAL_SESSION_URL,
  openLocalUrl,
  planLocalOpen,
  type OpenerEnvironment,
} from "./open-local-url.js";

/** #419. Nothing here starts a process: the spawn function is always a fake. */
const URL_WITH_TOKEN = "http://127.0.0.1:43123/#token=abcDEF012_-xyz";

function environment(overrides: Partial<OpenerEnvironment> = {}): OpenerEnvironment {
  return { platform: "darwin", env: {}, isTerminal: true, isDisabled: false, ...overrides };
}

describe("planLocalOpen", () => {
  it("macOS: /usr/bin/open with the URL as the only argument", () => {
    expect(planLocalOpen(URL_WITH_TOKEN, environment())).toEqual({
      kind: "open",
      command: "/usr/bin/open",
      args: [URL_WITH_TOKEN],
    });
  });

  it("Linux: xdg-open only with a display and never over SSH", () => {
    const linux = (env: Record<string, string>) =>
      planLocalOpen(URL_WITH_TOKEN, environment({ platform: "linux", env }));
    expect(linux({ DISPLAY: ":0" })).toEqual({
      kind: "open",
      command: "xdg-open",
      args: [URL_WITH_TOKEN],
    });
    expect(linux({ WAYLAND_DISPLAY: "wayland-0" }).kind).toBe("open");
    expect(linux({})).toEqual({ kind: "skip", reason: "no_display" });
    expect(linux({ DISPLAY: "" })).toEqual({ kind: "skip", reason: "no_display" });
    expect(linux({ DISPLAY: ":0", SSH_CONNECTION: "10.0.0.2 5000 10.0.0.1 22" })).toEqual({
      kind: "skip",
      reason: "ssh",
    });
    expect(linux({ WAYLAND_DISPLAY: "w", SSH_TTY: "/dev/pts/1" })).toEqual({
      kind: "skip",
      reason: "ssh",
    });
    // Other Unix-like platforms follow the Linux rules.
    expect(planLocalOpen(URL_WITH_TOKEN, environment({ platform: "freebsd", env: {} })).kind).toBe(
      "skip",
    );
  });

  it("Windows: rundll32 url.dll,FileProtocolHandler by absolute path, no shell string", () => {
    const plan = planLocalOpen(
      URL_WITH_TOKEN,
      environment({ platform: "win32", env: { SystemRoot: "D:\\Windows" } }),
    );
    expect(plan).toEqual({
      kind: "open",
      command: "D:\\Windows\\System32\\rundll32.exe",
      args: ["url.dll,FileProtocolHandler", URL_WITH_TOKEN],
    });
    const untrusted = planLocalOpen(
      URL_WITH_TOKEN,
      environment({ platform: "win32", env: { SystemRoot: "\\\\evil\\share" } }),
    );
    expect(untrusted.kind === "open" && untrusted.command).toBe(
      "C:\\Windows\\System32\\rundll32.exe",
    );
  });

  it("refuses any URL that is not exactly PGARD's own local URL, on every platform", () => {
    const bad = [
      "http://127.0.0.1:43123/#token=abc&calc.exe",
      "http://127.0.0.1:43123/#token=abc def",
      'http://127.0.0.1:43123/#token=abc"',
      "http://127.0.0.1:43123/#token=abc^&whoami",
      "http://localhost:43123/#token=abc",
      "https://127.0.0.1:43123/#token=abc",
      "http://127.0.0.1:43123/path#token=abc",
      "http://127.0.0.1:43123/?x=1",
      "http://127.0.0.1/#token=abc",
      "file:///C:/Windows/System32/calc.exe",
      " http://127.0.0.1:43123/",
      "http://127.0.0.1:43123/\n",
    ];
    for (const url of bad) {
      expect(LOCAL_SESSION_URL.test(url)).toBe(false);
      for (const platform of ["win32", "darwin", "linux"] as const) {
        expect(planLocalOpen(url, environment({ platform, env: { DISPLAY: ":0" } }))).toEqual({
          kind: "skip",
          reason: "bad_url",
        });
      }
    }
    expect(LOCAL_SESSION_URL.test("http://127.0.0.1:43123/")).toBe(true);
    expect(LOCAL_SESSION_URL.test(URL_WITH_TOKEN)).toBe(true);
  });

  it("does not open with --no-open, without a terminal or in CI", () => {
    expect(planLocalOpen(URL_WITH_TOKEN, environment({ isDisabled: true }))).toEqual({
      kind: "skip",
      reason: "disabled",
    });
    expect(planLocalOpen(URL_WITH_TOKEN, environment({ isTerminal: false }))).toEqual({
      kind: "skip",
      reason: "no_terminal",
    });
    expect(planLocalOpen(URL_WITH_TOKEN, environment({ env: { CI: "true" } }))).toEqual({
      kind: "skip",
      reason: "ci",
    });
  });
});

describe("openLocalUrl", () => {
  it("spawns the planned argv and reports a failed start", async () => {
    const spawn = vi.fn(async () => true);
    expect(await openLocalUrl(URL_WITH_TOKEN, environment(), spawn)).toEqual({ isOpened: true });
    expect(spawn).toHaveBeenCalledWith("/usr/bin/open", [URL_WITH_TOKEN]);
    const failing = vi.fn(async () => false);
    expect(await openLocalUrl(URL_WITH_TOKEN, environment(), failing)).toEqual({
      isOpened: false,
      reason: "failed",
    });
    const throwing = vi.fn(() => Promise.reject(new Error("boom")));
    expect((await openLocalUrl(URL_WITH_TOKEN, environment(), throwing)).isOpened).toBe(false);
  });

  it("never spawns when the plan says skip", async () => {
    const spawn = vi.fn(async () => true);
    await openLocalUrl(URL_WITH_TOKEN, environment({ platform: "linux", env: {} }), spawn);
    await openLocalUrl("http://127.0.0.1:1/#token=a&b", environment({ platform: "win32" }), spawn);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("is a separate opener: the source spawns with shell: false and an argv array", async () => {
    const source = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL("./open-local-url.ts", import.meta.url), "utf8"),
    );
    expect(source).toContain("shell: false");
    expect(source).not.toMatch(/exec\(|execSync|shell: true/);
  });
});
