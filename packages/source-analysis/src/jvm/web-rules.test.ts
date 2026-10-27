import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, path = "A.java") {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language);
  } finally {
    outcome.dispose();
  }
}

type Analysis = Awaited<ReturnType<typeof run>>;
const XSS = "PG-XSS-004";
const SSRF = "PG-SSRF-002";
const of = (analysis: Analysis, ruleId: string): RawSourceFinding[] =>
  analysis.findings.filter((finding) => finding.ruleId === ruleId);

/** Words for what a finding says: the design's own terms. */
function kind(findings: RawSourceFinding[]): string {
  if (findings.length === 0) return "none";
  const finding = findings[0] as RawSourceFinding;
  if (finding.confidence === "low") {
    return finding.evidence.includes("inferred") ? "inferred" : "untraced";
  }
  return `${finding.severity}/${finding.status}/${finding.confidence}`;
}

const SERVLET =
  "import javax.servlet.http.*;\nimport java.io.*;\nimport java.net.*;\nimport java.util.*;\n";
const SPRING =
  "import org.springframework.web.bind.annotation.*;\nimport org.springframework.web.client.RestTemplate;\nimport org.springframework.web.reactive.function.client.WebClient;\nimport org.springframework.web.util.*;\nimport java.net.*;\nimport java.util.*;\n";

const java = (imports: string, members: string): string => `${imports}\nclass A {\n${members}\n}\n`;
const servlet = (body: string, fields = ""): string =>
  java(
    SERVLET,
    `${fields}\nvoid h(HttpServletRequest req, HttpServletResponse resp) throws Exception {\nString p = req.getParameter("p");\n${body}\n}`,
  );
/** A Spring handler: `p` is request input. */
const handler = (body: string, imports = SPRING, fields = ""): string =>
  java(
    imports,
    `${fields}\nRestTemplate rest = new RestTemplate();\n@GetMapping("/x") void h(@RequestParam String p, @RequestParam String q) throws Exception {\n${body}\n}`,
  );

// ====================================================================== XSS

describe("PG-XSS-004: servlet writer", () => {
  const cases: Array<[string, string, string]> = [
    [
      "html content type and a parameter in markup",
      servlet('resp.setContentType("text/html");\nresp.getWriter().println("<h1>" + p + "</h1>");'),
      "high/suspected/high",
    ],
    [
      "no content type set",
      servlet('resp.getWriter().println("<h1>" + req.getParameter("n") + "</h1>");'),
      "high/confirmed/medium",
    ],
    [
      "writer in a variable",
      servlet('PrintWriter out = resp.getWriter();\nout.print("Hi " + p);'),
      "high/suspected/medium",
    ],
    [
      "output stream bytes",
      servlet('resp.getOutputStream().write(("<b>" + p + "</b>").getBytes());'),
      "high/suspected/medium",
    ],
    ["printf", servlet('resp.getWriter().printf("<p>%s</p>", p);'), "high/suspected/medium"],
    [
      "JSON content type is not XSS",
      servlet(
        'resp.setContentType("application/json");\nresp.getWriter().write("{\\"a\\":\\"" + p + "\\"}");',
      ),
      "none",
    ],
    [
      "plain text is not XSS",
      servlet('resp.setContentType("text/plain");\nresp.getWriter().write(p);'),
      "none",
    ],
    [
      "fixed text only",
      servlet('resp.setContentType("text/html");\nresp.getWriter().write("<h1>Hi</h1>");'),
      "none",
    ],
    [
      "html-escaped by a helper",
      servlet(
        'resp.setContentType("text/html");\nresp.getWriter().write("<p>" + HtmlUtils.htmlEscape(p) + "</p>");',
      ),
      "inferred",
    ],
    [
      "validated with a pattern before it exits",
      servlet(
        'resp.setContentType("text/html");\nif (!p.matches("[a-z]+")) { return; }\nresp.getWriter().write("<p>" + p + "</p>");',
      ),
      "inferred",
    ],
    [
      "a check that does not exit",
      servlet(
        'resp.setContentType("text/html");\nif (!p.matches("[a-z]+")) { log("bad"); }\nresp.getWriter().write("<p>" + p + "</p>");',
      ),
      "high/suspected/high",
    ],
  ];
  for (const [name, source, expected] of cases) {
    it(name, async () => {
      expect(kind(of(await run(source), XSS))).toBe(expected);
    });
  }
});

describe("PG-XSS-004: Spring handlers", () => {
  const html = (annotations: string, ret: string, body: string, cls = "@Controller"): string =>
    `import org.springframework.stereotype.Controller;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.http.*;\n${cls}\nclass A {\n${annotations}\n${ret} h(@RequestParam String p) {\n${body}\n}\n}\n`;
  it("a @ResponseBody String with produces text/html", async () => {
    const source = html(
      '@GetMapping(value = "/x", produces = "text/html")\n@ResponseBody',
      "String",
      'return "<p>" + p + "</p>";',
    );
    expect(kind(of(await run(source), XSS))).toBe("high/confirmed/high");
  });
  it("HTML text from a @RestController without produces", async () => {
    const source = html(
      '@GetMapping("/x")',
      "String",
      'return "<p>" + p + "</p>";',
      "@RestController",
    );
    expect(kind(of(await run(source), XSS))).toBe("high/confirmed/medium");
  });
  it("a plain String from a @RestController is low confidence", async () => {
    const source = html('@GetMapping("/x")', "String", "return p;", "@RestController");
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
  it("JSON produces is not XSS", async () => {
    const source = html(
      '@GetMapping(value = "/x", produces = MediaType.APPLICATION_JSON_VALUE)',
      "String",
      'return "{\\"a\\":\\"" + p + "\\"}";',
      "@RestController",
    );
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
  it("a DTO or Map from a @RestController is JSON", async () => {
    const source = html(
      '@GetMapping("/x")',
      "java.util.Map<String, String>",
      'return java.util.Map.of("a", p);',
      "@RestController",
    );
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
  it("a @Controller view name is not a response body", async () => {
    const source = html('@GetMapping("/x")', "String", 'return "view-" + p;');
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
  it("ResponseEntity with an HTML content type", async () => {
    const source = html(
      '@GetMapping("/x")',
      "ResponseEntity<String>",
      'return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body("<b>" + p + "</b>");',
      "@RestController",
    );
    expect(kind(of(await run(source), XSS))).toBe("high/confirmed/high");
  });
  it("a thrown message is not a response body", async () => {
    const source = html(
      '@GetMapping("/x")',
      "String",
      'throw new IllegalArgumentException("bad " + p);',
      "@RestController",
    );
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
});

describe("PG-XSS-004: Kotlin", () => {
  it("Ktor respondText with an HTML content type", async () => {
    const source = `import io.ktor.server.application.*\nimport io.ktor.server.response.*\nimport io.ktor.http.*\nsuspend fun h(call: ApplicationCall) {\nval name = call.parameters["name"]\ncall.respondText("<h1>$name</h1>", ContentType.Text.Html)\n}\n`;
    expect(kind(of(await run(source, "K.kt"), XSS))).toBe("high/suspected/high");
  });
  it("Ktor respondText defaults to plain text", async () => {
    const source = `import io.ktor.server.application.*\nimport io.ktor.server.response.*\nsuspend fun h(call: ApplicationCall) {\nval name = call.parameters["name"]\ncall.respondText("<h1>$name</h1>")\n}\n`;
    expect(kind(of(await run(source, "K.kt"), XSS))).toBe("none");
  });
  it("a servlet writer in Kotlin", async () => {
    const source = `import javax.servlet.http.*\nfun h(req: HttpServletRequest, resp: HttpServletResponse) {\nresp.contentType = "text/html"\nresp.writer.write("<p>" + req.getParameter("p") + "</p>")\n}\n`;
    expect(kind(of(await run(source, "K.kt"), XSS))).toBe("high/confirmed/high");
  });
});

// ====================================================================== SSRF

describe("PG-SSRF-002: URL sinks", () => {
  const cases: Array<[string, string, string]> = [
    ["URL.openStream", handler("new URL(p).openStream();"), "high/confirmed/high"],
    [
      "URL variable then openConnection",
      handler("URL u = new URL(p);\nu.openConnection();"),
      "high/suspected/high",
    ],
    [
      "URI.create into HttpRequest.newBuilder",
      handler(
        "var req = java.net.http.HttpRequest.newBuilder(URI.create(p)).build();",
        SPRING + "import java.net.http.*;\n",
      ),
      "high/confirmed/high",
    ],
    [
      "HttpRequest.Builder.uri",
      handler(
        "var req = java.net.http.HttpRequest.newBuilder().uri(URI.create(p)).build();",
        SPRING + "import java.net.http.*;\n",
      ),
      "high/confirmed/high",
    ],
    [
      "RestTemplate.getForObject",
      handler("rest.getForObject(p, String.class);"),
      "high/confirmed/high",
    ],
    [
      "RestTemplate.exchange",
      handler('rest.exchange("http://" + p + "/x", HttpMethod.GET, null, String.class);'),
      "high/confirmed/high",
    ],
    [
      "WebClient.get().uri",
      handler("WebClient.create().get().uri(p).retrieve();"),
      "high/confirmed/high",
    ],
    [
      "OkHttp Request.Builder().url",
      handler("new okhttp3.Request.Builder().url(p).build();", SPRING + "import okhttp3.*;\n"),
      "high/confirmed/high",
    ],
    [
      "Apache HttpGet",
      handler("new HttpGet(p);", SPRING + "import org.apache.http.client.methods.HttpGet;\n"),
      "high/confirmed/high",
    ],
    [
      "Jsoup.connect",
      handler("org.jsoup.Jsoup.connect(p).get();", SPRING + "import org.jsoup.*;\n"),
      "high/confirmed/high",
    ],
    [
      "a fixed base URL with a path from the request",
      handler('rest.getForObject("https://api.example.com/users/" + p, String.class);'),
      "inferred",
    ],
    [
      "a fixed base URL with a query from the request",
      handler('new URL("https://api.example.com/search?q=" + p).openStream();'),
      "inferred",
    ],
    [
      "the host comes from the request",
      handler('rest.getForObject("https://" + p + ".example.com/x", String.class);'),
      "high/confirmed/high",
    ],
    [
      "a fixed URL",
      handler('rest.getForObject("https://api.example.com/health", String.class);'),
      "none",
    ],
    [
      "URI template variables are encoded and the URL is fixed",
      handler('rest.getForObject("https://api.example.com/users/{id}", String.class, p);'),
      "none",
    ],
    [
      "UriComponentsBuilder with a fixed host and a path segment",
      handler(
        'URI u = UriComponentsBuilder.fromHttpUrl("https://api.example.com").pathSegment(p).build().toUri();\nrest.getForObject(u, String.class);',
      ),
      "inferred",
    ],
    [
      "allowlisted host with an exit guard",
      handler(
        'URI u = URI.create(p);\nif (!ALLOWED.contains(u.getHost())) { throw new IllegalArgumentException("host"); }\nrest.getForObject(u, String.class);',
        SPRING,
        'static final Set<String> ALLOWED = Set.of("a.example.com");',
      ),
      "inferred",
    ],
    [
      "host variable checked, then the URL is used",
      handler(
        "String host = new URL(p).getHost();\nif (!ALLOWED.contains(host)) { return; }\nrest.getForObject(p, String.class);",
        SPRING,
        'static final Set<String> ALLOWED = Set.of("a.example.com");',
      ),
      "inferred",
    ],
    [
      "use inside the success branch",
      handler(
        "if (ALLOWED.contains(new URL(p).getHost())) {\nrest.getForObject(p, String.class);\n}",
        SPRING,
        'static final Set<String> ALLOWED = Set.of("a.example.com");',
      ),
      "inferred",
    ],
    [
      "a host check that does not exit",
      handler(
        'if (!ALLOWED.contains(new URL(p).getHost())) { System.out.println("odd"); }\nrest.getForObject(p, String.class);',
        SPRING,
        'static final Set<String> ALLOWED = Set.of("a.example.com");',
      ),
      "high/confirmed/high",
    ],
    [
      "a private-address check that exits",
      handler(
        "InetAddress a = InetAddress.getByName(new URL(p).getHost());\nif (a.isSiteLocalAddress() || a.isLoopbackAddress()) { throw new IllegalArgumentException(); }\nrest.getForObject(p, String.class);",
      ),
      "inferred",
    ],
    [
      "a lookup in a fixed table",
      handler(
        "rest.getForObject(FEEDS.get(p), String.class);",
        SPRING,
        'static final java.util.Map<String, String> FEEDS = java.util.Map.of("a", "https://a.example.com/feed");',
      ),
      "inferred",
    ],
    [
      "an unknown parameter of the method itself",
      java(
        SPRING,
        "RestTemplate rest;\nString f(String url) {\nreturn rest.getForObject(url, String.class);\n}",
      ),
      "inferred",
    ],
  ];
  for (const [name, source, expected] of cases) {
    it(name, async () => {
      expect(kind(of(await run(source), SSRF))).toBe(expected);
    });
  }
});

describe("PG-SSRF-002: Kotlin", () => {
  it("Ktor client.get with a request parameter", async () => {
    const source = `import io.ktor.client.*\nimport io.ktor.client.request.*\nimport io.ktor.server.application.*\nsuspend fun h(call: ApplicationCall, client: HttpClient) {\nval u = call.parameters["url"]!!\nclient.get(u)\n}\n`;
    expect(kind(of(await run(source, "K.kt"), SSRF))).toBe("high/suspected/high");
  });
  it("a Kotlin template with a fixed host", async () => {
    const source = `import io.ktor.client.*\nimport io.ktor.client.request.*\nimport io.ktor.server.application.*\nsuspend fun h(call: ApplicationCall, client: HttpClient) {\nval id = call.parameters["id"]!!\nclient.get("https://api.example.com/users/$id")\n}\n`;
    expect(kind(of(await run(source, "K.kt"), SSRF))).toBe("inferred");
  });
  it("URL(...).readText()", async () => {
    const source = `import org.springframework.web.bind.annotation.*\nimport java.net.URL\n@RestController\nclass K {\n@GetMapping("/x")\nfun h(@RequestParam url: String): String = URL(url).readText()\n}\n`;
    expect(kind(of(await run(source, "K.kt"), SSRF))).toBe("high/confirmed/high");
  });
  it("host in an allowlist with a require() guard", async () => {
    const source = `import io.ktor.client.*\nimport io.ktor.client.request.*\nimport java.net.URI\nsuspend fun f(client: HttpClient, url: String) {\nval host = URI(url).host\nrequire(host in ALLOWED_HOSTS) { "host" }\nclient.get(url)\n}\nval ALLOWED_HOSTS = setOf("a.example.com")\n`;
    expect(kind(of(await run(source, "K.kt"), SSRF))).toBe("inferred");
  });
});

describe("web rules: other forms", () => {
  it("reports an escape-helper result only at low confidence", async () => {
    const source = servlet(
      'resp.setContentType("text/html");\nresp.getWriter().write(StringEscapeUtils.escapeHtml4(p));',
    );
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
});
