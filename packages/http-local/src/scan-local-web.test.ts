import type http from "node:http";
import type { ConfirmedWebTarget } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import { CORS_PROBE_ORIGIN } from "./constants.js";
import { AUTHENTICATED_NOT_AVAILABLE_NOTE, scanLocalWeb } from "./scan-local-web.js";
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

function targetFor(port: number): ConfirmedWebTarget {
  return { port, origin: `http://127.0.0.1:${port}`, title: null, confirmedByUser: true };
}

const SECRET_VALUE = "sk_live_DO_NOT_LEAK_123456";

function vulnerableApp(request: http.IncomingMessage, response: http.ServerResponse): void {
  const origin = request.headers.origin;
  const corsHeaders: Record<string, string> =
    typeof origin === "string"
      ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" }
      : {};
  switch (request.url) {
    case "/":
      response.writeHead(200, {
        "content-type": "text/html",
        server: "nginx/1.25.3",
        "x-powered-by": "Express",
        "set-cookie": [`sid=${SECRET_VALUE}; Path=/`],
        ...corsHeaders,
      });
      response.end(`<title>Vulnerable</title>
        <a href="/files/">files</a> <a href="/logout">logout</a>
        <a href="/about?token=${SECRET_VALUE}">about</a> <a href="http://example.com/">ext</a>`);
      return;
    case "/files/":
      response
        .writeHead(200, { "content-type": "text/html" })
        .end("<title>Index of /files/</title>");
      return;
    case "/about":
      response.writeHead(200, { "content-type": "text/html" }).end("<title>About</title>");
      return;
    case "/.env":
      response
        .writeHead(200, { "content-type": "text/plain" })
        .end(`API_KEY=${SECRET_VALUE}\nDEBUG=1\n`);
      return;
    case "/.git/HEAD":
      response.writeHead(200, { "content-type": "text/plain" }).end("ref: refs/heads/main\n");
      return;
    default:
      response.writeHead(404).end();
  }
}

describe("scanLocalWeb", () => {
  it("finds header, cookie, CORS, disclosure, listing and exposure issues without leaking values", async () => {
    const server = await start(vulnerableApp);
    const output = await scanLocalWeb(targetFor(server.port), {});
    const ruleIds = output.findings.map((finding) => finding.ruleId).sort();
    expect(ruleIds).toEqual([
      "PG-WEB-001",
      "PG-WEB-002",
      "PG-WEB-003",
      "PG-WEB-004",
      "PG-WEB-005",
      "PG-WEB-006",
      "PG-WEB-007",
      "PG-WEB-009",
      "PG-WEB-010",
      "PG-WEB-011",
      "PG-WEB-012",
      "PG-WEB-013",
    ]);
    const serialized = JSON.stringify(output);
    expect(serialized).not.toContain(SECRET_VALUE);
    expect(serialized).not.toContain("token=");
    for (const finding of output.findings) {
      expect(finding.location.kind).toBe("url");
      expect(finding.location.url?.startsWith(`http://127.0.0.1:${server.port}/`)).toBe(true);
      expect(finding.sources).toEqual(["web"]);
    }
    // Header absence is never reported as a confirmed vulnerability.
    const headerFinding = output.findings.find((finding) => finding.ruleId === "PG-WEB-001");
    expect(headerFinding?.status).toBe("informational");

    // Only GET requests, only to the target, never to the logout link.
    expect(new Set(server.requests.map((request) => request.method))).toEqual(new Set(["GET"]));
    expect(server.requests.map((request) => request.url)).not.toContain("/logout");
    expect(server.requests.some((request) => request.url?.includes("token"))).toBe(false);
    expect(server.requests.some((request) => request.headers.origin === CORS_PROBE_ORIGIN)).toBe(
      true,
    );

    expect(output.coverage).toEqual([
      expect.objectContaining({ area: "web:anonymous", scope: "web", status: "completed" }),
      {
        area: "web:authenticated",
        scope: "web",
        status: "not_selected",
        ruleIds: [],
        note: AUTHENTICATED_NOT_AVAILABLE_NOTE,
      },
    ]);
  });

  it("never reports query strings picked up from redirects", async () => {
    const server = await start((request, response) => {
      if (request.url === "/") {
        response.writeHead(302, { location: "/login?session=SECRET123" }).end();
        return;
      }
      response
        .writeHead(200, { "content-type": "text/html", "set-cookie": ["sid=x"] })
        .end("<title>Login</title>");
    });
    const progressUrls: string[] = [];
    const output = await scanLocalWeb(targetFor(server.port), {
      onProgress: (progress) => progressUrls.push(progress.url),
    });
    expect(output.findings.length).toBeGreaterThan(0);
    expect(JSON.stringify(output)).not.toContain("SECRET123");
    expect(progressUrls.join(" ")).not.toContain("SECRET123");
    expect(output.findings[0]?.location.url).toBe(`http://127.0.0.1:${server.port}/login`);
  });

  it("reports nothing for a hardened app whose SPA fallback serves HTML for every path", async () => {
    const server = await start((_request, response) => {
      response.writeHead(200, {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "set-cookie": ["sid=abc; HttpOnly; Secure; SameSite=Lax"],
      });
      response.end("<title>Safe</title><p>API_KEY=not-a-file</p>");
    });
    const output = await scanLocalWeb(targetFor(server.port), {});
    expect(output.findings).toEqual([]);
    expect(output.coverage[0]?.status).toBe("completed");
  });

  it("records wildcard CORS with credentials as a separate rule", async () => {
    const server = await start((_request, response) => {
      response
        .writeHead(200, {
          "content-type": "application/json",
          "access-control-allow-origin": "*",
          "access-control-allow-credentials": "true",
        })
        .end("{}");
    });
    const output = await scanLocalWeb(targetFor(server.port), {});
    expect(output.findings.map((finding) => finding.ruleId)).toContain("PG-WEB-008");
  });

  it("marks coverage partial when the page limit is reached", async () => {
    const server = await start((request, response) => {
      const links = Array.from({ length: 10 }, (_, index) => `<a href="/p${index}">p</a>`).join("");
      response
        .writeHead(200, { "content-type": "text/html" })
        .end(`<title>${request.url}</title>${links}`);
    });
    const output = await scanLocalWeb(targetFor(server.port), { limits: { maxPages: 3 } });
    expect(output.coverage[0]?.status).toBe("partial");
    expect(output.coverage[0]?.note).toContain("page limit of 3 reached");
    // 3 crawled pages + CORS probe + .env + .git/HEAD
    expect(server.requests).toHaveLength(6);
  });

  it("does not follow a root redirect to an external host", async () => {
    const server = await start((_request, response) => {
      response.writeHead(302, { location: "http://example.invalid/" }).end();
    });
    const output = await scanLocalWeb(targetFor(server.port), {});
    expect(output.coverage[0]?.status).toBe("partial");
    expect(output.coverage[0]?.note).toContain("redirect leaving 127.0.0.1");
  });

  it("does not follow a redirect to another loopback port", async () => {
    const other = await start((_request, response) => response.end("other"));
    const server = await start((_request, response) => {
      response.writeHead(302, { location: `http://127.0.0.1:${other.port}/` }).end();
    });
    await scanLocalWeb(targetFor(server.port), {});
    expect(other.requests).toHaveLength(0);
  });

  it("returns not_tested for an unconfirmed or non-loopback target without sending requests", async () => {
    const server = await start((_request, response) => response.end());
    const unconfirmed = {
      ...targetFor(server.port),
      confirmedByUser: false,
    } as unknown as ConfirmedWebTarget;
    const output = await scanLocalWeb(unconfirmed, {});
    expect(output.coverage[0]?.status).toBe("not_tested");
    const foreign = { ...targetFor(server.port), origin: "http://example.com:80" };
    expect((await scanLocalWeb(foreign, {})).coverage[0]?.status).toBe("not_tested");
    expect(server.requests).toHaveLength(0);
  });

  it("returns not_tested when the service does not answer", async () => {
    const server = await start(() => {
      /* never answers */
    });
    const output = await scanLocalWeb(targetFor(server.port), {
      limits: { requestTimeoutMs: 100 },
    });
    expect(output.coverage[0]?.status).toBe("not_tested");
    expect(output.findings).toEqual([]);
  });

  it("keeps slow redirect chains within the total time budget", async () => {
    const server = await start((request, response) => {
      const hop = Number(request.url?.replace(/\D/g, "") || "0");
      setTimeout(() => response.writeHead(302, { location: `/r${hop + 1}` }).end(), 150);
    });
    const startedAt = Date.now();
    const output = await scanLocalWeb(targetFor(server.port), { limits: { totalBudgetMs: 500 } });
    expect(Date.now() - startedAt).toBeLessThan(900);
    expect(output.coverage[0]?.status).not.toBe("completed");
  });

  it("stops when the total time budget is exhausted", async () => {
    const server = await start((_request, response) => {
      response.writeHead(200, { "content-type": "text/html" }).end('<a href="/a">a</a>');
    });
    let clock = 0;
    const output = await scanLocalWeb(targetFor(server.port), {
      limits: { totalBudgetMs: 1000 },
      now: () => {
        clock += 600;
        return clock;
      },
    });
    expect(output.coverage[0]?.note).toContain("time budget");
  });
});
