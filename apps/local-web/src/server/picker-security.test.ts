import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  apiGet,
  apiPost,
  json,
  send,
  startHarness,
  SESSION,
  TOKEN,
  type Harness,
  type RawResponse,
} from "./test-support/web-harness.js";
import { repoCandidate } from "./test-support/fake-inspector.js";

let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
});

const ID = "AAAAAAAAAAAAAAAAAAAAAA";

/** Every picker route with a body that would be valid in picker mode. */
const PICKER_ROUTES: Array<{ method: "GET" | "POST"; path: string; body?: unknown }> = [
  { method: "GET", path: "/api/picker/scope" },
  { method: "POST", path: "/api/picker/scope/toggle", body: { rootId: ID, enabled: false } },
  { method: "POST", path: "/api/picker/search", body: { source: "typed", name: "shop", epoch: 1 } },
  { method: "GET", path: `/api/picker/search?id=${ID}` },
  { method: "POST", path: "/api/picker/search/cancel", body: { searchId: ID } },
  { method: "GET", path: "/api/picker/recent" },
  { method: "POST", path: "/api/picker/recent/remove", body: { entryId: ID } },
  { method: "POST", path: "/api/picker/confirm", body: { candidateId: ID, shown: "x", epoch: 1 } },
  { method: "POST", path: "/api/picker/clear", body: { epoch: 1 } },
];

function headersFor(
  port: number,
  overrides: Record<string, string | null> = {},
  method = "POST",
): Record<string, string> {
  const headers: Record<string, string | null> = {
    "x-pgard-session": SESSION,
    ...(method === "POST"
      ? { origin: `http://127.0.0.1:${port}`, "content-type": "application/json" }
      : {}),
    ...overrides,
  };
  return Object.fromEntries(
    Object.entries(headers).filter((entry): entry is [string, string] => entry[1] !== null),
  );
}

function request(
  running: Harness,
  route: (typeof PICKER_ROUTES)[number],
  overrides: Record<string, string | null> = {},
  extra: { body?: string } = {},
): Promise<RawResponse> {
  return send(running.server, route.method, route.path, {
    headers: headersFor(running.server.port, overrides, route.method),
    ...(route.method === "POST" ? { body: extra.body ?? JSON.stringify(route.body ?? {}) } : {}),
  });
}

describe("picker routes reuse the existing request checks (design test 1)", () => {
  for (const route of PICKER_ROUTES) {
    describe(`${route.method} ${route.path.split("?")[0]}`, () => {
      it("needs the token, our Host and our Origin, and sends no CORS header", async () => {
        harness = await startHarness();
        const port = harness.server.port;
        const rejected: Array<[string, RawResponse]> = [
          ["no token", await request(harness, route, { "x-pgard-session": null })],
          ["wrong token", await request(harness, route, { "x-pgard-session": "nope" })],
          ["localhost host", await request(harness, route, { host: `localhost:${port}` })],
          ["rebound name", await request(harness, route, { host: `evil.example:${port}` })],
          ["foreign origin", await request(harness, route, { origin: "http://evil.example" })],
          ["cross-site fetch", await request(harness, route, { "sec-fetch-site": "cross-site" })],
          ["wrong content type", await request(harness, route, { "content-type": "text/plain" })],
        ];
        if (route.method === "POST") {
          rejected.push(["missing origin", await request(harness, route, { origin: null })]);
          rejected.push([
            "body over 16 KiB",
            await request(
              harness,
              route,
              {},
              { body: JSON.stringify({ pad: "x".repeat(17 * 1024) }) },
            ),
          ]);
        }
        const expected: Record<string, number> = {
          "no token": 401,
          "wrong token": 401,
          "localhost host": 421,
          "rebound name": 421,
          "foreign origin": 403,
          "cross-site fetch": 403,
          "wrong content type": route.method === "POST" ? 415 : 200,
          "missing origin": 403,
          "body over 16 KiB": 413,
        };
        for (const [label, response] of rejected) {
          if (label === "wrong content type" && route.method === "GET") continue;
          expect(response.status, label).toBe(expected[label]);
          expect(
            Object.keys(response.headers).filter((key) => key.startsWith("access-control-")),
          ).toEqual([]);
          expect(response.headers["cache-control"]).toBe("no-store");
        }
        // Nothing was searched or selected by any rejected request.
        expect(harness.inspector.runs).toHaveLength(0);
        expect(harness.server.state.project).toBeNull();
      });
    });
  }

  it("sends no CORS header on a successful answer or an error either", async () => {
    harness = await startHarness();
    for (const response of [
      await apiGet(harness.server, "/api/picker/scope"),
      await apiPost(harness.server, "/api/picker/search", { source: "typed", name: "x", epoch: 1 }),
      await apiGet(harness.server, "/api/picker/search?id=bad"),
    ]) {
      expect(Object.keys(response.headers).some((key) => key.startsWith("access-control-"))).toBe(
        false,
      );
    }
  });

  it("answers a preflight-style OPTIONS request without approving anything", async () => {
    harness = await startHarness();
    const response = await send(harness.server, "OPTIONS", "/api/picker/search", {
      headers: { origin: "http://evil.example", "access-control-request-method": "POST" },
    });
    expect(response.status).toBe(403); // the foreign Origin is refused first, like any request
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
    expect(response.headers["access-control-allow-methods"]).toBeUndefined();
  });

  it("accepts no WebSocket or other upgrade", async () => {
    harness = await startHarness();
    const port = harness.server.port;
    const reply = await new Promise<string>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(
          [
            "GET /api/picker/scope HTTP/1.1",
            `Host: 127.0.0.1:${port}`,
            `x-pgard-session: ${SESSION}`,
            "Connection: Upgrade",
            "Upgrade: websocket",
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "",
            "",
          ].join("\r\n"),
        );
      });
      let received = "";
      socket.on("data", (chunk) => (received += chunk.toString()));
      socket.on("close", () => resolve(received));
      socket.on("error", () => resolve(received));
      setTimeout(() => {
        socket.destroy();
        resolve(received);
      }, 500);
    });
    expect(reply.startsWith("HTTP/1.1 101")).toBe(false);
    expect(reply).not.toContain("Sec-WebSocket-Accept");
  });
});

describe("fixed mode: pgard dashboard refuses every picker route (design test 2)", () => {
  const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
  const bodies: Array<[string, string]> = [
    ["a valid body", JSON.stringify({ source: "typed", name: "shop", epoch: 1 })],
    ["an invalid body", JSON.stringify({ name: 42 })],
    ["broken JSON", "{not json"],
    ["an empty body", ""],
  ];

  it("answers 409 fixed_project for every method, route and body, before reading the body", async () => {
    harness = await startHarness({ fixedRoot: "/work/my-project" });
    harness.inspector.repos.set("shop", [repoCandidate("shop")]);
    const paths = [
      ...PICKER_ROUTES.map((route) => route.path),
      "/api/picker/unknown",
      "/api/picker/search/extra",
    ];
    for (const path of paths) {
      for (const method of methods) {
        for (const [label, body] of bodies) {
          const attempt = () =>
            send(harness!.server, method, path, {
              headers: headersFor(harness!.server.port, {}, method === "GET" ? "GET" : "POST"),
              ...(method === "GET" ? {} : { body }),
            });
          // The server answers before reading the body (that is the point), so the client may
          // see the connection reset while it is still writing; the answer is the same on retry.
          const isReset = (error: unknown): boolean =>
            ["ECONNRESET", "EPIPE"].includes((error as { code?: string }).code ?? "");
          const retry = (error: unknown) => {
            if (!isReset(error)) throw error;
            return attempt();
          };
          const response = await attempt().catch(retry).catch(retry);
          expect(response.status, `${method} ${path} ${label}`).toBe(409);
          expect(json(response).error).toMatchObject({ code: "fixed_project" });
        }
      }
    }
    expect(harness.inspector.runs).toHaveLength(0);
    expect(harness.server.state.project?.root).toBe("/work/my-project");
    expect(harness.server.state.projectEpoch).toBe(1);
  });

  it("still requires the token first, so a stranger learns nothing about the mode", async () => {
    harness = await startHarness({ fixedRoot: "/work/my-project" });
    const response = await send(harness.server, "GET", "/api/picker/scope");
    expect(response.status).toBe(401);
  });

  it("reports the mode in the session", async () => {
    harness = await startHarness({ fixedRoot: "/work/my-project" });
    expect(json(await apiGet(harness.server, "/api/session"))).toMatchObject({
      mode: "fixed",
      project: { name: "my-project", repo: null },
      projectEpoch: 1,
    });
  });
});
