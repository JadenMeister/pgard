// Headless Chrome driven over the DevTools protocol (no dependencies). Only file:// and
// 127.0.0.1 pages are opened; nothing here starts a visible browser.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CANDIDATES = [
  process.env.CHROME,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function launchChrome() {
  const binary = CANDIDATES.find((path) => path !== undefined && existsSync(path));
  if (binary === undefined) throw new Error("Chrome not found; set CHROME=/path/to/chrome");
  const profile = mkdtempSync(join(tmpdir(), "pgard-shots-"));
  const child = spawn(
    binary,
    [
      "--headless=new",
      "--remote-debugging-port=0",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-gpu",
      "--hide-scrollbars",
      "--force-color-profile=srgb",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--disable-domain-reliability",
      "--metrics-recording-only",
      "--no-pings",
      "about:blank",
    ],
    { stdio: "ignore" },
  );
  let port;
  let path;
  for (let attempt = 0; attempt < 100 && path === undefined; attempt += 1) {
    await sleep(100);
    try {
      [port, path] = readFileSync(join(profile, "DevToolsActivePort"), "utf8").trim().split("\n");
    } catch {
      // not written yet
    }
  }
  const cleanup = () => {
    child.kill();
    rmSync(profile, { recursive: true, force: true });
  };
  if (path === undefined) {
    cleanup();
    throw new Error("Chrome did not start");
  }
  const socket = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  try {
    await new Promise((resolve, reject) => {
      socket.onopen = resolve;
      socket.onerror = reject;
    });
  } catch (error) {
    cleanup();
    throw error;
  }
  let nextId = 1;
  const pending = new Map();
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    const waiter = pending.get(message.id);
    if (waiter === undefined) return;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(message.error.message));
    else waiter.resolve(message.result);
  };
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = nextId;
      nextId += 1;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params, sessionId }));
    });

  /** Opens a page, runs `body(page)`, closes it. */
  async function withPage(options, body) {
    const { width, height, scale = 2, locale = "en-US", dark = true } = options;
    const { targetId } = await send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    const call = (method, params) => send(method, params, sessionId);
    await call("Page.enable");
    await call("Emulation.setDeviceMetricsOverride", {
      width,
      height,
      deviceScaleFactor: scale,
      mobile: false,
    });
    await call("Emulation.setLocaleOverride", { locale });
    await call("Emulation.setUserAgentOverride", {
      userAgent: "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/150 Safari/537.36",
      acceptLanguage: locale,
    });
    await call("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }],
    });
    const page = {
      call,
      async goto(url) {
        await call("Page.navigate", { url });
        await sleep(400);
        for (let i = 0; i < 100; i += 1) {
          const state = await call("Runtime.evaluate", { expression: "document.readyState" });
          if (state.result.value === "complete") break;
          await sleep(100);
        }
        await call("Runtime.evaluate", {
          expression: "document.fonts ? document.fonts.ready.then(() => true) : true",
          awaitPromise: true,
        });
      },
      async eval(expression) {
        const out = await call("Runtime.evaluate", {
          expression,
          awaitPromise: true,
          returnByValue: true,
        });
        if (out.exceptionDetails) throw new Error(out.exceptionDetails.text);
        return out.result.value;
      },
      sleep,
      async waitFor(expression, timeout = 15000) {
        const until = Date.now() + timeout;
        while (Date.now() < until) {
          if (await page.eval(expression)) return;
          await sleep(150);
        }
        throw new Error(`timed out waiting for ${expression}`);
      },
      /** PNG of the viewport, or of `clip` ({x, y, width, height} in CSS pixels). */
      async screenshot(clip) {
        const out = await call("Page.captureScreenshot", {
          format: "png",
          clip: clip === undefined ? undefined : { ...clip, scale: 1 },
        });
        return Buffer.from(out.data, "base64");
      },
    };
    try {
      return await body(page);
    } finally {
      await send("Target.closeTarget", { targetId }).catch(() => {});
    }
  }

  async function close() {
    socket.close();
    child.kill();
    await sleep(300);
    rmSync(profile, { recursive: true, force: true });
  }
  return { withPage, close };
}
