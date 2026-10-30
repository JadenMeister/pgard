import { afterEach, describe, expect, it } from "vitest";
import { startLocalWebServer, type LocalWebServer } from "./create-server.js";
import { fakeDeps, send, TOKEN } from "./test-support/web-harness.js";

/**
 * #419 review: the browser arrives at the page from the redirect file (`file://`), which
 * browsers send as `Sec-Fetch-Site: cross-site`. Only that top-level navigation of the HTML
 * document is allowed; everything else stays as strict as before.
 */
let running: LocalWebServer | null = null;
afterEach(async () => {
  await running?.close();
  running = null;
});

async function start(): Promise<LocalWebServer> {
  running = await startLocalWebServer({
    projectRoot: null,
    presetTargetPort: null,
    env: {},
    assets: new Map([
      ["/", { body: Buffer.from("<html></html>"), contentType: "text/html; charset=utf-8" }],
      ["/assets/app.js", { body: Buffer.from("1"), contentType: "text/javascript" }],
    ]),
    deps: fakeDeps(),
    token: TOKEN,
  });
  return running;
}

const NAVIGATION = {
  "sec-fetch-site": "cross-site",
  "sec-fetch-mode": "navigate",
  "sec-fetch-dest": "document",
};

describe("the page reached from the redirect file", () => {
  it("serves / to a cross-site top-level navigation without Origin", async () => {
    const server = await start();
    const page = await send(server, "GET", "/", { headers: NAVIGATION });
    expect(page.status).toBe(200);
    expect(page.headers["x-frame-options"]).toBe("DENY");
    expect(String(page.headers["content-security-policy"])).toContain("frame-ancestors 'none'");
    expect((await send(server, "HEAD", "/", { headers: NAVIGATION })).status).toBe(200);
  });

  it("keeps the API strict for the same headers", async () => {
    const server = await start();
    expect((await send(server, "GET", "/api/session", { headers: NAVIGATION })).status).toBe(403);
    const exchange = await send(server, "POST", "/api/session/exchange", {
      headers: { ...NAVIGATION, "content-type": "application/json" },
      body: JSON.stringify({ token: TOKEN }),
    });
    expect(exchange.status).toBe(403);
    // The refused exchange did not spend the link.
    const good = await send(server, "POST", "/api/session/exchange", {
      headers: { origin: `http://127.0.0.1:${server.port}`, "content-type": "application/json" },
      body: JSON.stringify({ token: TOKEN }),
    });
    expect(good.status).toBe(200);
  });

  it("still refuses a cross-site subresource or fetch of the page, an Origin, and other files", async () => {
    const server = await start();
    const refused: Array<Record<string, string>> = [
      { "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "empty" },
      { "sec-fetch-site": "cross-site", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
      { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "iframe" },
      { "sec-fetch-site": "cross-site", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "document" },
      { ...NAVIGATION, origin: "http://evil.example" },
      { ...NAVIGATION, origin: "null" },
      { "sec-fetch-site": "cross-site" },
    ];
    for (const headers of refused) {
      expect((await send(server, "GET", "/", { headers })).status, JSON.stringify(headers)).toBe(
        403,
      );
    }
    expect((await send(server, "GET", "/assets/app.js", { headers: NAVIGATION })).status).toBe(403);
    expect(
      (await send(server, "GET", "/", { headers: { host: "localhost", ...NAVIGATION } })).status,
    ).toBe(421);
    // Same-origin and direct visits are unchanged.
    expect((await send(server, "GET", "/", { headers: { "sec-fetch-site": "none" } })).status).toBe(
      200,
    );
    expect((await send(server, "GET", "/assets/app.js")).status).toBe(200);
  });
});
