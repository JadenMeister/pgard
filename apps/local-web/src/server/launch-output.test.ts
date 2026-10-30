import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  announceLaunch,
  connectedLine,
  launcherLanguage,
  launchLines,
  maskSessionUrl,
  reusedLine,
} from "./launch-output.js";
import type { OpenerEnvironment } from "./open-local-url.js";
import { createRedirectFile } from "./redirect-file.js";

/** #419: what the terminal shows. No browser is ever started here (the spawn is a fake). */
const TOKEN = "abcDEF0123456789_-tokenvalue";
const URL = `http://127.0.0.1:43123/#token=${TOKEN}`;

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const env = (overrides: Partial<OpenerEnvironment> = {}): OpenerEnvironment => ({
  platform: "darwin",
  env: {},
  isTerminal: true,
  isDisabled: false,
  ...overrides,
});

async function run(options: {
  printUrl?: boolean;
  environment?: OpenerEnvironment;
  opens?: boolean;
}) {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgard-launch-test-"));
  roots.push(root);
  let text = "";
  const spawn = vi.fn(async (_command: string, _args: readonly string[]) => options.opens ?? true);
  const { open, redirect } = await announceLaunch({
    url: URL,
    mode: "picker",
    printUrl: options.printUrl ?? false,
    environment: options.environment ?? env(),
    write: (chunk) => (text += chunk),
    deps: { spawn, createRedirect: (url) => createRedirectFile(url, { tmpRoot: root }) },
  });
  return { text, spawn, outcome: open, redirect };
}

describe("maskSessionUrl", () => {
  it("hides the token", () => {
    expect(maskSessionUrl(URL)).toBe("http://127.0.0.1:43123/#token=••••");
  });
});

describe.skipIf(process.platform === "win32")("announceLaunch", () => {
  it("opens the redirect file and shows the link with the token masked", async () => {
    const { text, spawn, redirect } = await run({});
    expect(spawn).toHaveBeenCalledWith("/usr/bin/open", [redirect?.file]);
    expect(JSON.stringify(spawn.mock.calls)).not.toContain(TOKEN);
    expect(text).toContain("Opened in your browser: http://127.0.0.1:43123/#token=••••");
    expect(text).toContain(
      "If no browser opened (or the file opened in an editor), run again with --print-url.",
    );
    expect(text).not.toContain(TOKEN);
  });

  it("--print-url also prints the full link", async () => {
    const { text } = await run({ printUrl: true });
    expect(text).toContain("#token=••••");
    expect(text).toContain(`Full one-time link: ${URL}`);
  });

  it("--no-open opens nothing and prints the full link", async () => {
    const { text, spawn, redirect } = await run({ environment: env({ isDisabled: true }) });
    expect(spawn).not.toHaveBeenCalled();
    expect(redirect).toBeNull();
    expect(text).toContain("Not opened automatically (--no-open or --no-browser was given).");
    expect(text).toContain(`Open this one-time link in your browser: ${URL}`);
  });

  it("prints the full link when the opener failed (for example xdg-open exited non-zero)", async () => {
    const { text, outcome, redirect } = await run({
      opens: false,
      environment: env({ platform: "linux", env: { DISPLAY: ":0" } }),
    });
    expect(outcome).toEqual({ isOpened: false, reason: "failed" });
    expect(redirect).toBeNull();
    expect(text).toContain("the browser could not be started");
    expect(text).toContain(URL);
  });

  it("prints the full link without a terminal, in CI and over SSH (also on a Mac)", async () => {
    for (const environment of [
      env({ isTerminal: false }),
      env({ env: { CI: "1" } }),
      env({ env: { SSH_CONNECTION: "a b c d" } }),
      env({ platform: "linux", env: { DISPLAY: ":0", SSH_TTY: "/dev/pts/0" } }),
    ]) {
      const { text, spawn } = await run({ environment });
      expect(spawn).not.toHaveBeenCalled();
      expect(text).toContain(URL);
    }
  });
});

describe("launchLines", () => {
  it("names the command that discards the results", () => {
    const opened = { isOpened: true } as const;
    expect(
      launchLines({ url: URL, mode: "picker", printUrl: false, open: opened }).join("\n"),
    ).toContain("when pgard web stops");
    const fixed = launchLines({ url: URL, mode: "fixed", printUrl: false, open: opened }).join(
      "\n",
    );
    expect(fixed).toContain("PGARD dashboard is running");
    expect(fixed).toContain("when pgard dashboard stops");
  });
});

describe("the no-browser hint", () => {
  it("is Korean with PGARD_LANG=ko, English otherwise", () => {
    expect(launcherLanguage({ PGARD_LANG: "ko" })).toBe("ko");
    expect(launcherLanguage({ PGARD_LANG: "en" })).toBe("en");
    expect(launcherLanguage({ PGARD_LANG: "kor" })).toBe("en");
    expect(launcherLanguage({})).toBe("en");
    const opened = { isOpened: true } as const;
    const korean = launchLines({
      url: URL,
      mode: "picker",
      printUrl: false,
      open: opened,
      language: "ko",
    });
    expect(korean.join("\n")).toContain(
      "브라우저가 안 열렸다면(또는 편집기에서 열렸다면) --print-url로 다시 실행하세요.",
    );
  });
});

describe("terminal lines on exchange", () => {
  it("prints the local time of a connection and of a reuse attempt", () => {
    const at = new Date(2026, 9, 30, 23, 41, 7);
    expect(connectedLine(at)).toBe("Browser connected at 23:41:07.\n");
    expect(reusedLine(at)).toContain("Someone tried to reuse the link at 23:41:07.");
  });
});
