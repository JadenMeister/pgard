import { afterEach, describe, expect, it } from "vitest";
import { createConfirmedWebTarget, isExplicitYes, probeLocalService } from "./probe.js";
import { startFixtureServer, type FixtureServer } from "./test-fixtures.js";

let server: FixtureServer | null = null;
afterEach(async () => {
  await server?.close();
  server = null;
});

describe("probeLocalService", () => {
  it("shows URL, status, title and inferred technologies", async () => {
    server = await startFixtureServer((_request, response) => {
      response
        .writeHead(200, { "content-type": "text/html", "x-powered-by": "Express" })
        .end("<title>Shop dev</title>");
    });
    const identity = await probeLocalService(server.port);
    expect(identity).toEqual({
      port: server.port,
      url: `http://127.0.0.1:${server.port}/`,
      status: 200,
      title: "Shop dev",
      inferredTechnologies: ["Express"],
      isHttp: true,
      redirectStop: null,
      error: null,
    });
  });

  it("reports a closed port without throwing", async () => {
    server = await startFixtureServer((_request, response) => response.end());
    const port = server.port;
    await server.close();
    server = null;
    const identity = await probeLocalService(port);
    expect(identity.isHttp).toBe(false);
    expect(identity.status).toBeNull();
    expect(identity.error).not.toBeNull();
  });
});

describe("createConfirmedWebTarget", () => {
  const identity = {
    port: 4000,
    url: "http://127.0.0.1:4000/",
    status: 200,
    title: "App",
    inferredTechnologies: [],
    isHttp: true,
    redirectStop: null,
    error: null,
  };

  it("requires an explicit yes", () => {
    expect(() => createConfirmedWebTarget(identity, false)).toThrow();
    expect(createConfirmedWebTarget(identity, true)).toEqual({
      port: 4000,
      origin: "http://127.0.0.1:4000",
      title: "App",
      confirmedByUser: true,
    });
  });

  it("refuses ports that did not answer HTTP", () => {
    expect(() => createConfirmedWebTarget({ ...identity, isHttp: false }, true)).toThrow();
  });
});

describe("isExplicitYes", () => {
  it.each([
    ["y", true],
    ["Y", true],
    ["yes", true],
    [" YES ", true],
    ["", false],
    ["n", false],
    ["no", false],
    ["yep", false],
    ["1", false],
  ])("%j -> %s", (answer, expected) => {
    expect(isExplicitYes(answer)).toBe(expected);
  });
});
