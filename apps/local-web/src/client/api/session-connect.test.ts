import { afterEach, describe, expect, it, vi } from "vitest";
import {
  apiGet,
  connectSession,
  hasSessionToken,
  resetSessionForTests,
  SESSION_STORAGE_KEY,
  setSessionEndedListener,
  takeTokenFromLocation,
} from "./client";

/** #419: the page trades the link's one-time token for a per-tab session secret. */
const URL_TOKEN = "urltoken0123456789abcdefghijklmnopqrstu";
const SECRET = "sessionsecret0123456789abcdefghijklmnopq";

function memoryStore(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
    removeItem: (key: string) => void data.delete(key),
  };
}

function openLink(hash = `#token=${URL_TOKEN}`): void {
  takeTokenFromLocation(
    { hash, pathname: "/", search: "" } as Location,
    { replaceState: () => undefined } as unknown as History,
  );
}

type Reply = { status: number; body: unknown };
function stubServer(replies: Record<string, Reply | Reply[]>) {
  const calls: Array<{ path: string; init: RequestInit }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init: RequestInit) => {
      calls.push({ path, init });
      const entry = replies[path];
      const reply = Array.isArray(entry) ? (entry.shift() ?? entry[0]) : entry;
      if (reply === undefined) throw new TypeError("network");
      return new Response(JSON.stringify(reply.body), { status: reply.status });
    }),
  );
  return calls;
}

const used = { status: 409, body: { error: { code: "token_used", message: "m" } } };

afterEach(() => {
  vi.unstubAllGlobals();
  resetSessionForTests();
  setSessionEndedListener(null);
});

describe("connectSession", () => {
  it("exchanges the link once, keeps the secret in this tab and sends it as x-pgard-session", async () => {
    const store = memoryStore();
    const calls = stubServer({
      "/api/session/exchange": { status: 200, body: { session: SECRET } },
      "/api/session": { status: 200, body: {} },
    });
    openLink();
    // Strict mode runs effects twice: both share one exchange.
    const [first, second] = await Promise.all([connectSession(store), connectSession(store)]);
    expect([first, second]).toEqual(["connected", "connected"]);
    const exchanges = calls.filter((call) => call.path === "/api/session/exchange");
    expect(exchanges).toHaveLength(1);
    expect(JSON.parse(String(exchanges[0]?.init.body))).toEqual({ token: URL_TOKEN });
    expect(exchanges[0]?.init.credentials).toBe("omit");
    expect(store.data.get(SESSION_STORAGE_KEY)).toBe(SECRET);
    expect(hasSessionToken()).toBe(true);

    await apiGet("/api/session");
    const headers = calls.at(-1)?.init.headers as Record<string, string>;
    expect(headers["x-pgard-session"]).toBe(SECRET);
    expect(Object.keys(headers)).not.toContain("x-pgard-token");
    expect(JSON.stringify(calls.slice(1))).not.toContain(URL_TOKEN);
  });

  it("a reload of the same tab reuses the stored secret without a link", async () => {
    const store = memoryStore({ [SESSION_STORAGE_KEY]: SECRET });
    const calls = stubServer({ "/api/session": { status: 200, body: {} } });
    expect(await connectSession(store)).toBe("connected");
    expect(calls.map((call) => call.path)).toEqual(["/api/session"]);
    expect((calls[0]?.init.headers as Record<string, string>)["x-pgard-session"]).toBe(SECRET);
  });

  it("the same link in another tab: 'used'", async () => {
    stubServer({ "/api/session/exchange": used });
    openLink();
    expect(await connectSession(memoryStore())).toBe("used");
    expect(hasSessionToken()).toBe(false);
  });

  it("the same tab opening the used link again keeps its own session", async () => {
    const store = memoryStore({ [SESSION_STORAGE_KEY]: SECRET });
    const calls = stubServer({
      "/api/session": { status: 200, body: {} },
      "/api/session/exchange": used,
    });
    openLink();
    expect(await connectSession(store)).toBe("connected");
    expect(calls.some((call) => call.path === "/api/session/exchange")).toBe(false);
  });

  it("maps expired links, ended sessions, a missing link, a foreign link and no server", async () => {
    const cases: Array<[() => void, Record<string, Reply>, Record<string, string>, string]> = [
      [
        openLink,
        { "/api/session/exchange": { status: 410, body: { error: { code: "token_expired" } } } },
        {},
        "expired",
      ],
      [
        () => undefined,
        { "/api/session": { status: 401, body: { error: { code: "session_expired" } } } },
        { [SESSION_STORAGE_KEY]: SECRET },
        "ended",
      ],
      [() => undefined, {}, {}, "no_link"],
      [
        openLink,
        { "/api/session/exchange": { status: 401, body: { error: { code: "bad_token" } } } },
        {},
        "invalid",
      ],
      [openLink, {}, {}, "unreachable"],
    ];
    for (const [setup, replies, stored, expected] of cases) {
      resetSessionForTests();
      stubServer(replies);
      setup();
      const store = memoryStore(stored);
      expect(await connectSession(store)).toBe(expected);
      if (expected === "ended") expect(store.data.has(SESSION_STORAGE_KEY)).toBe(false);
    }
  });

  it("tells the page when the session ends later (idle timeout)", async () => {
    stubServer({
      "/api/session/exchange": { status: 200, body: { session: SECRET } },
      "/api/session": { status: 401, body: { error: { code: "session_expired", message: "m" } } },
    });
    openLink();
    await connectSession(memoryStore());
    const ended = vi.fn();
    setSessionEndedListener(ended);
    await expect(apiGet("/api/session")).rejects.toMatchObject({ code: "session_expired" });
    expect(ended).toHaveBeenCalledTimes(1);
    expect(hasSessionToken()).toBe(false);
  });

  it("ignores a malformed stored value", async () => {
    stubServer({});
    expect(await connectSession(memoryStore({ [SESSION_STORAGE_KEY]: "<x>" }))).toBe("no_link");
  });
});
