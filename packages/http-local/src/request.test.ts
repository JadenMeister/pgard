import { afterEach, describe, expect, it } from "vitest";
import { fetchLoopback, LoopbackRequestError, requestLoopbackOnce } from "./request.js";
import { startFixtureServer, type FixtureServer } from "./test-fixtures.js";

const servers: FixtureServer[] = [];
async function start(...args: Parameters<typeof startFixtureServer>): Promise<FixtureServer> {
  const server = await startFixtureServer(...args);
  servers.push(server);
  return server;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe("fetchLoopback redirects", () => {
  it("stops at a redirect to an external host without contacting it", async () => {
    const server = await start((_request, response) => {
      response.writeHead(302, { location: "http://example.invalid/steal" }).end();
    });
    const result = await fetchLoopback(server.port, "/");
    expect(result.redirectStop).toEqual({
      reason: "off_target",
      fromUrl: `http://127.0.0.1:${server.port}/`,
    });
    expect(result.response.status).toBe(302);
    expect(server.requests).toHaveLength(1);
  });

  it("stops at a redirect to another loopback port", async () => {
    const other = await start((_request, response) => response.end("other"));
    const server = await start((_request, response) => {
      response.writeHead(301, { location: `http://127.0.0.1:${other.port}/` }).end();
    });
    const result = await fetchLoopback(server.port, "/");
    expect(result.redirectStop?.reason).toBe("off_target");
    expect(other.requests).toHaveLength(0);
  });

  it("stops at a redirect to localhost (hostname) even on the same port", async () => {
    const server = await start((request, response) => {
      response.writeHead(302, { location: `http://localhost:${request.socket.localPort}/` }).end();
    });
    const result = await fetchLoopback(server.port, "/");
    expect(result.redirectStop?.reason).toBe("off_target");
  });

  it("follows relative redirects on the same loopback origin", async () => {
    const server = await start((request, response) => {
      if (request.url === "/") {
        response.writeHead(302, { location: "/home" }).end();
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" }).end("home");
    });
    const result = await fetchLoopback(server.port, "/");
    expect(result.redirectStop).toBeNull();
    expect(result.response.url).toBe(`http://127.0.0.1:${server.port}/home`);
    expect(result.response.body.toString()).toBe("home");
  });

  it("follows redirects with their query but reports the path only", async () => {
    const server = await start((request, response) => {
      if (request.url === "/") {
        response.writeHead(302, { location: "/next?token=abc" }).end();
        return;
      }
      response.end("ok");
    });
    const result = await fetchLoopback(server.port, "/");
    expect(server.requests.map((request) => request.url)).toEqual(["/", "/next?token=abc"]);
    expect(result.response.url).toBe(`http://127.0.0.1:${server.port}/next`);
  });

  it("does not follow redirects to logout/delete-like paths", async () => {
    const server = await start((request, response) => {
      if (request.url === "/go") {
        response.writeHead(302, { location: "/logout" }).end();
        return;
      }
      response.end("should not be reached");
    });
    const result = await fetchLoopback(server.port, "/go");
    expect(result.redirectStop?.reason).toBe("unsafe_path");
    expect(server.requests.map((request) => request.url)).toEqual(["/go"]);
  });

  it("stops redirect loops", async () => {
    const server = await start((_request, response) => {
      response.writeHead(302, { location: "/" }).end();
    });
    const result = await fetchLoopback(server.port, "/");
    expect(result.redirectStop?.reason).toBe("too_many_redirects");
    expect(server.requests.length).toBeLessThanOrEqual(6);
  });
});

describe("fetchLoopback timeouts", () => {
  it("applies one timeout to the whole redirect chain", async () => {
    const server = await start((request, response) => {
      const hop = Number(request.url?.slice(1) || "0");
      setTimeout(() => response.writeHead(302, { location: `/${hop + 1}` }).end(), 150);
    });
    const startedAt = Date.now();
    await expect(fetchLoopback(server.port, "/", { timeoutMs: 400 })).rejects.toMatchObject({
      code: "timeout",
    });
    expect(Date.now() - startedAt).toBeLessThan(700);
    expect(server.requests.length).toBeLessThanOrEqual(3);
  });
});

describe("requestLoopbackOnce", () => {
  it("only sends GET or HEAD", async () => {
    const server = await start((_request, response) => response.end());
    expect(() => requestLoopbackOnce(server.port, "/", { method: "POST" as never })).toThrow();
    await requestLoopbackOnce(server.port, "/", { method: "HEAD" });
    await requestLoopbackOnce(server.port, "/");
    expect(server.requests.map((request) => request.method)).toEqual(["HEAD", "GET"]);
  });

  it("caps the body size", async () => {
    const server = await start((_request, response) => response.end("x".repeat(10_000)));
    const response = await requestLoopbackOnce(server.port, "/", { maxBodyBytes: 100 });
    expect(response.body.length).toBe(100);
    expect(response.isBodyTruncated).toBe(true);
  });

  it("times out slow services", async () => {
    const server = await start(() => {
      /* never answers */
    });
    await expect(requestLoopbackOnce(server.port, "/", { timeoutMs: 100 })).rejects.toMatchObject({
      code: "timeout",
    });
  });

  it("reports connection failures as network errors", async () => {
    const server = await start((_request, response) => response.end());
    const port = server.port;
    await server.close();
    servers.length = 0;
    const error = await requestLoopbackOnce(port, "/").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(LoopbackRequestError);
    expect((error as LoopbackRequestError).code).toBe("network");
  });

  it("rejects paths that are not absolute", async () => {
    expect(() => requestLoopbackOnce(80, "http://example.com/")).toThrow();
  });
});
