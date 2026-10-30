import { describe, expect, it, vi } from "vitest";
import { announceLaunch, connectedLine, launchLines, maskSessionUrl } from "./launch-output.js";
import type { OpenerEnvironment } from "./open-local-url.js";

/** #419: what the terminal shows. No browser is ever started here (the spawn is a fake). */
const TOKEN = "abcDEF0123456789_-tokenvalue";
const URL = `http://127.0.0.1:43123/#token=${TOKEN}`;

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
  let text = "";
  const spawn = vi.fn(async () => options.opens ?? true);
  const outcome = await announceLaunch({
    url: URL,
    mode: "picker",
    printUrl: options.printUrl ?? false,
    environment: options.environment ?? env(),
    write: (chunk) => (text += chunk),
    spawn,
  });
  return { text, spawn, outcome };
}

describe("maskSessionUrl", () => {
  it("hides the token", () => {
    expect(maskSessionUrl(URL)).toBe("http://127.0.0.1:43123/#token=••••");
  });
});

describe("announceLaunch", () => {
  it("opens the browser and shows the link with the token masked", async () => {
    const { text, spawn } = await run({});
    expect(spawn).toHaveBeenCalledWith("/usr/bin/open", [URL]);
    expect(text).toContain("Opened in your browser: http://127.0.0.1:43123/#token=••••");
    expect(text).toContain("--print-url");
    expect(text).not.toContain(TOKEN);
  });

  it("--print-url also prints the full link", async () => {
    const { text } = await run({ printUrl: true });
    expect(text).toContain("#token=••••");
    expect(text).toContain(`Full one-time link: ${URL}`);
  });

  it("--no-open opens nothing and prints the full link", async () => {
    const { text, spawn } = await run({ environment: env({ isDisabled: true }) });
    expect(spawn).not.toHaveBeenCalled();
    expect(text).toContain("Not opened automatically (--no-open or --no-browser was given).");
    expect(text).toContain(`Open this one-time link in your browser: ${URL}`);
  });

  it("prints the full link when the browser could not be started", async () => {
    const { text, outcome } = await run({ opens: false });
    expect(outcome).toEqual({ isOpened: false, reason: "failed" });
    expect(text).toContain("the browser could not be started");
    expect(text).toContain(URL);
  });

  it("prints the full link without a terminal, in CI and over SSH", async () => {
    for (const environment of [
      env({ isTerminal: false }),
      env({ env: { CI: "1" } }),
      env({ platform: "linux", env: { DISPLAY: ":0", SSH_CONNECTION: "a b c d" } }),
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

describe("connectedLine", () => {
  it("prints the local time of the exchange", () => {
    expect(connectedLine(new Date(2026, 9, 30, 23, 41, 7))).toBe(
      "Browser connected at 23:41:07.\n",
    );
  });
});
