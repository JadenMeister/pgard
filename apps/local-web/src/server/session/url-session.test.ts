import { timingSafeEqual } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createUrlSession, SESSION_IDLE_MS, URL_TOKEN_TTL_MS } from "./url-session.js";

const TOKEN = "url-token-0123456789abcdefghijklmnopqrstu";
const T0 = 1_000_000;

describe("createUrlSession", () => {
  it("exchanges the URL token once for a 32-byte secret, then refuses it as used", () => {
    const session = createUrlSession(TOKEN, T0);
    const first = session.exchange(TOKEN, T0 + 1);
    expect(first.kind).toBe("ok");
    const secret = first.kind === "ok" ? first.secret : "";
    expect(Buffer.from(secret, "base64url")).toHaveLength(32);
    expect(secret).not.toBe(TOKEN);
    expect(session.exchange(TOKEN, T0 + 2)).toEqual({ kind: "token_used" });
    expect(session.check(secret, T0 + 3)).toEqual({ kind: "ok" });
  });

  it("answers 'used' only for the real token: anything else is just a bad token", () => {
    const session = createUrlSession(TOKEN, T0);
    session.exchange(TOKEN, T0);
    for (const other of [`${TOKEN}x`, TOKEN.slice(0, -1), "", "x".repeat(500), 42, null]) {
      expect(session.exchange(other, T0)).toEqual({ kind: "bad_token" });
    }
  });

  it("lets an unused token expire after 10 minutes", () => {
    const fresh = createUrlSession(TOKEN, T0);
    expect(fresh.exchange(TOKEN, T0 + URL_TOKEN_TTL_MS).kind).toBe("ok");
    const late = createUrlSession(TOKEN, T0);
    expect(late.exchange(TOKEN, T0 + URL_TOKEN_TTL_MS + 1)).toEqual({ kind: "token_expired" });
    // An expired token is not spent by the refusal, but it never becomes valid again.
    expect(late.exchange(TOKEN, T0 + URL_TOKEN_TTL_MS + 2)).toEqual({ kind: "token_expired" });
  });

  it("ends the session after 30 minutes without a call; every call restarts the wait", () => {
    const session = createUrlSession(TOKEN, T0, {
      newSecret: () => "secret-abcdefghijklmnopqrstuvwxyz",
    });
    session.exchange(TOKEN, T0);
    const secret = "secret-abcdefghijklmnopqrstuvwxyz";
    expect(session.check(secret, T0 + SESSION_IDLE_MS).kind).toBe("ok");
    expect(session.check(secret, T0 + 2 * SESSION_IDLE_MS).kind).toBe("ok");
    expect(session.check(secret, T0 + 3 * SESSION_IDLE_MS + 1)).toEqual({ kind: "expired" });
    // Gone for good: the same secret is not accepted again.
    expect(session.check(secret, T0 + 3 * SESSION_IDLE_MS + 2)).toEqual({ kind: "invalid" });
  });

  it("refuses a missing or wrong secret, and any secret before the exchange", () => {
    const session = createUrlSession(TOKEN, T0);
    expect(session.check(undefined, T0)).toEqual({ kind: "missing" });
    expect(session.check("", T0)).toEqual({ kind: "missing" });
    // The URL token itself is never a session secret.
    expect(session.check(TOKEN, T0)).toEqual({ kind: "invalid" });
    const outcome = session.exchange(TOKEN, T0);
    const secret = outcome.kind === "ok" ? outcome.secret : "";
    expect(session.check(`${secret}x`, T0)).toEqual({ kind: "invalid" });
    expect(session.check(TOKEN, T0)).toEqual({ kind: "invalid" });
  });

  it("compares hashes in constant time (timingSafeEqual on equal-length buffers)", () => {
    const equal = vi.fn((a: Buffer, b: Buffer) => timingSafeEqual(a, b));
    const session = createUrlSession(TOKEN, T0, { equal });
    session.exchange("wrong-token-of-another-length", T0);
    const outcome = session.exchange(TOKEN, T0);
    session.check(outcome.kind === "ok" ? outcome.secret : "", T0);
    session.check("wrong", T0);
    expect(equal).toHaveBeenCalledTimes(4);
    for (const [a, b] of equal.mock.calls) expect(a.length).toBe(b.length);
  });

  it("uses crypto.timingSafeEqual by default", async () => {
    const source = await import("node:fs/promises").then((fs) =>
      fs.readFile(new URL("./url-session.ts", import.meta.url), "utf8"),
    );
    expect(source).toContain("deps.equal ?? timingSafeEqual");
    expect(source).not.toMatch(/===\s*(token|secret|candidate)\b/);
  });
});
