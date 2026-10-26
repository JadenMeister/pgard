import type http from "node:http";
import type { ConfirmedWebTarget } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import { WEB_RULE_IDS } from "./rules.js";
import { WEB_AREA_ANONYMOUS, scanLocalWeb } from "./scan-local-web.js";
import { startFixtureServer, type FixtureServer } from "./test-fixtures.js";

const servers: FixtureServer[] = [];
async function start(handler: http.RequestListener): Promise<FixtureServer> {
  const server = await startFixtureServer(handler);
  servers.push(server);
  return server;
}
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

const targetFor = (port: number): ConfirmedWebTarget => ({
  port,
  origin: `http://127.0.0.1:${port}`,
  title: null,
  confirmedByUser: true,
});

function app(request: http.IncomingMessage, response: http.ServerResponse): void {
  switch (request.url) {
    case "/":
      response.writeHead(200, { "content-type": "text/html", "set-cookie": ["sid=abc; Path=/"] });
      response.end('<a href="/files/">files</a> <a href="/about">about</a>');
      return;
    case "/files/":
      response
        .writeHead(200, { "content-type": "text/html" })
        .end("<title>Index of /files/</title>");
      return;
    case "/about":
      response.writeHead(200, { "content-type": "text/html" }).end("<title>About</title>");
      return;
    default:
      response.writeHead(404).end();
  }
}

type Output = Awaited<ReturnType<typeof scanLocalWeb>>;
const stat = (output: Output, ruleId: string) =>
  output.ruleStats?.find((row) => row.ruleId === ruleId);

describe("scanLocalWeb rule stats", () => {
  it("counts the pages and responses each web rule really looked at", async () => {
    const server = await start(app);
    const output = await scanLocalWeb(targetFor(server.port), {});
    // / , /files/ , /about are crawled; then the CORS probe, /.env and /.git/HEAD (404 answers
    // still count as responses).
    expect(stat(output, "PG-WEB-005")).toMatchObject({
      area: WEB_AREA_ANONYMOUS,
      scope: "web",
      status: "completed",
      targets: [{ unit: "responses", examined: 6, reason: null }],
      findings: 1,
    });
    expect(stat(output, "PG-WEB-011")).toMatchObject({
      targets: [{ unit: "pages", examined: 3 }],
      findings: 1,
    });
    expect(stat(output, "PG-WEB-001")?.targets).toEqual([
      { unit: "responses", examined: 1, reason: null },
    ]);
    expect(stat(output, "PG-WEB-008")?.targets[0]?.examined).toBe(1);
    expect(stat(output, "PG-WEB-012")?.targets[0]?.examined).toBe(1);
    expect(stat(output, "PG-WEB-013")?.targets[0]?.examined).toBe(1);
    expect(stat(output, "PG-WEB-012")?.findings).toBe(0);
  });

  it("lists every web rule exactly once when the area ran", async () => {
    const server = await start(app);
    const output = await scanLocalWeb(targetFor(server.port), {});
    expect(output.ruleStats?.map((row) => row.ruleId).sort()).toEqual([...WEB_RULE_IDS].sort());
  });

  it("does not claim a header check when / was an unfollowed redirect", async () => {
    const server = await start((request, response) => {
      if (request.url === "/") {
        response.writeHead(302, { location: "http://example.com/" }).end();
        return;
      }
      response.writeHead(404).end();
    });
    const output = await scanLocalWeb(targetFor(server.port), {});
    expect(output.coverage[0]?.status).toBe("partial");
    expect(stat(output, "PG-WEB-001")?.targets[0]?.examined).toBe(0);
    expect(stat(output, "PG-WEB-001")?.status).toBe("partial");
  });

  it("reports no stats when the service did not answer", async () => {
    const server = await start(app);
    const port = server.port;
    await server.close();
    servers.splice(servers.indexOf(server), 1);
    const output = await scanLocalWeb(targetFor(port), {});
    expect(output.coverage[0]?.status).toBe("not_tested");
    expect(output.ruleStats).toBeUndefined();
  });
});
