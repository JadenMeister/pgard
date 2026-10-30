import { afterEach, describe, expect, it, vi } from "vitest";
import { startLocalWebServer, type LocalWebServer } from "./create-server.js";
import { SESSION_IDLE_MS, URL_TOKEN_TTL_MS } from "./session/url-session.js";
import { fakeDeps, json, send, TOKEN, type RawResponse } from "./test-support/web-harness.js";

/** #419: the URL token is an invitation, spent once for a per-tab session secret. */
let running: LocalWebServer | null = null;
let clock = { now: 5_000_000 };
const connected: Date[] = [];

afterEach(async () => {
  await running?.close();
  running = null;
  connected.length = 0;
});

async function start(): Promise<LocalWebServer> {
  clock = { now: 5_000_000 };
  running = await startLocalWebServer({
    projectRoot: null,
    presetTargetPort: null,
    env: {},
    assets: new Map(),
    deps: fakeDeps(),
    token: TOKEN,
    sessionClock: () => clock.now,
    onBrowserConnected: (at) => connected.push(at),
  });
  return running;
}

function exchange(
  server: LocalWebServer,
  token: unknown,
  headers: Record<string, string> = {},
): Promise<RawResponse> {
  return send(server, "POST", "/api/session/exchange", {
    headers: {
      origin: `http://127.0.0.1:${server.port}`,
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify({ token }),
  });
}

const read = (server: LocalWebServer, headers: Record<string, string>) =>
  send(server, "GET", "/api/session", { headers });

const code = (response: RawResponse) =>
  (json(response).error as { code: string } | undefined)?.code;

describe("POST /api/session/exchange", () => {
  it("succeeds once, then answers 409 token_used", async () => {
    const server = await start();
    const first = await exchange(server, TOKEN);
    expect(first.status).toBe(200);
    const secret = json(first).session as string;
    expect(Buffer.from(secret, "base64url").length).toBeGreaterThanOrEqual(32);
    expect(connected).toHaveLength(1);

    const second = await exchange(server, TOKEN);
    expect(second.status).toBe(409);
    expect(code(second)).toBe("token_used");
    expect(second.body).not.toContain(secret);
    expect(connected).toHaveLength(1);

    expect((await read(server, { "x-pgard-session": secret })).status).toBe(200);
  });

  it("answers 401 for any other token, before and after the real one was used", async () => {
    const server = await start();
    for (const token of ["nope", `${TOKEN}x`, 7, null]) {
      const response = await exchange(server, token);
      expect(response.status).toBe(401);
      expect(code(response)).toBe("bad_token");
    }
    await exchange(server, TOKEN);
    expect((await exchange(server, "nope")).status).toBe(401);
  });

  it("expires an unused token after 10 minutes (410 token_expired)", async () => {
    const server = await start();
    clock.now += URL_TOKEN_TTL_MS + 1;
    const response = await exchange(server, TOKEN);
    expect(response.status).toBe(410);
    expect(code(response)).toBe("token_expired");
    expect(connected).toHaveLength(0);
  });

  it("keeps the Host and Origin checks", async () => {
    const server = await start();
    expect((await exchange(server, TOKEN, { host: `localhost:${server.port}` })).status).toBe(421);
    expect((await exchange(server, TOKEN, { origin: "http://evil.example" })).status).toBe(403);
    expect((await exchange(server, TOKEN, { "sec-fetch-site": "cross-site" })).status).toBe(403);
    const noOrigin = await send(server, "POST", "/api/session/exchange", {
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: TOKEN }),
    });
    expect(noOrigin.status).toBe(403);
    expect((await send(server, "GET", "/api/session/exchange")).status).toBe(404);
    // None of the refusals spent the token.
    expect((await exchange(server, TOKEN)).status).toBe(200);
  });
});

describe("the session secret on every other route", () => {
  it("is required: the URL token, a wrong secret or none get 401", async () => {
    const server = await start();
    const secret = json(await exchange(server, TOKEN)).session as string;
    const cases: Array<[Record<string, string>, string]> = [
      [{}, "missing_session"],
      [{ "x-pgard-session": "wrong-secret-0123456789abcdefghijk" }, "bad_session"],
      // The raw URL token is accepted by no route, in either header.
      [{ "x-pgard-session": TOKEN }, "bad_session"],
      [{ "x-pgard-token": TOKEN }, "missing_session"],
      [{ "x-pgard-token": secret }, "missing_session"],
    ];
    for (const [headers, expected] of cases) {
      const response = await read(server, headers);
      expect(response.status).toBe(401);
      expect(code(response)).toBe(expected);
    }
    const post = await send(server, "POST", "/api/scan/cancel", {
      headers: {
        origin: `http://127.0.0.1:${server.port}`,
        "content-type": "application/json",
        "x-pgard-token": TOKEN,
      },
      body: "{}",
    });
    expect(post.status).toBe(401);
  });

  it("refuses every API route before the exchange", async () => {
    const server = await start();
    for (const path of ["/api/session", "/api/auth/status", "/api/scan", "/api/picker/recent"]) {
      const withToken = await send(server, "GET", path, { headers: { "x-pgard-token": TOKEN } });
      expect(withToken.status).toBe(401);
      expect((await send(server, "GET", path)).status).toBe(401);
    }
  });

  it("works again on a reload (the same secret) and ends after 30 minutes idle", async () => {
    const server = await start();
    const secret = json(await exchange(server, TOKEN)).session as string;
    const headers = { "x-pgard-session": secret };
    clock.now += SESSION_IDLE_MS - 1;
    expect((await read(server, headers)).status).toBe(200);
    clock.now += SESSION_IDLE_MS - 1;
    expect((await read(server, headers)).status).toBe(200);
    clock.now += SESSION_IDLE_MS + 1;
    const expired = await read(server, headers);
    expect(expired.status).toBe(401);
    expect(code(expired)).toBe("session_expired");
    expect(code(await read(server, headers))).toBe("bad_session");
    // The spent URL token does not bring the session back.
    expect((await exchange(server, TOKEN)).status).toBe(409);
  });

  it("never writes the token or the secret to the console", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((name) =>
      vi.spyOn(console, name).mockImplementation(() => undefined),
    );
    const server = await start();
    const secret = json(await exchange(server, TOKEN)).session as string;
    await exchange(server, TOKEN);
    await read(server, { "x-pgard-session": secret });
    for (const spy of spies) {
      for (const call of spy.mock.calls) {
        const text = call.map(String).join(" ");
        expect(text).not.toContain(TOKEN);
        expect(text).not.toContain(secret);
      }
      spy.mockRestore();
    }
  });
});
