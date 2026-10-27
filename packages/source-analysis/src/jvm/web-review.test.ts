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

function kind(findings: RawSourceFinding[]): string {
  if (findings.length === 0) return "none";
  const finding = findings[0] as RawSourceFinding;
  if (finding.confidence === "low") return "inferred";
  return `${finding.severity}/${finding.status}/${finding.confidence}`;
}

const SERVLET =
  "import javax.servlet.http.*;\nimport java.io.*;\nimport java.net.*;\nimport java.util.*;\nimport org.springframework.web.util.HtmlUtils;\n";
const SPRING =
  "import org.springframework.web.bind.annotation.*;\nimport org.springframework.web.client.RestTemplate;\nimport org.springframework.web.util.*;\nimport java.net.*;\nimport java.util.*;\n";

const java = (imports: string, members: string): string => `${imports}\nclass A {\n${members}\n}\n`;
const servlet = (body: string, fields = ""): string =>
  java(
    SERVLET,
    `${fields}\nvoid h(HttpServletRequest req, HttpServletResponse resp) throws Exception {\nString p = req.getParameter("p");\n${body}\n}`,
  );
const handler = (body: string): string =>
  java(
    SPRING,
    `RestTemplate rest = new RestTemplate();\n@GetMapping("/x") void h(@RequestParam String p) throws Exception {\n${body}\n}`,
  );

describe("PG-XSS-004: handler returns are demoted, not dropped", () => {
  const body = (produces: boolean, expression: string, extra = ""): string =>
    `import org.springframework.web.bind.annotation.*;\nimport org.springframework.web.util.HtmlUtils;\n@RestController\nclass A {\n${extra}\n@GetMapping(value = "/x"${produces ? ', produces = "text/html"' : ""}) String h(@RequestParam String name) {\n${expression}\n}\n}\n`;
  it("an escaped value is low confidence", async () => {
    const source = body(false, 'return "<p>" + HtmlUtils.htmlEscape(name) + "</p>";');
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
  it("a helper result is low confidence and says so, once", async () => {
    const found = of(await run(body(false, "return render(name);")), XSS);
    expect(kind(found)).toBe("inferred");
    expect(found[0]?.evidence).toContain("value from render()");
    expect(found[0]?.evidence.match(/inferred/g)).toHaveLength(1);
  });
  it("a field is low confidence", async () => {
    const source = body(false, "return banner;", "String banner;");
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
  it("a literal is silent", async () => {
    expect(kind(of(await run(body(false, 'return "<p>hi</p>";')), XSS))).toBe("none");
  });
  it("a JSON serialiser result is silent", async () => {
    const source = body(false, "return mapper.writeValueAsString(name);", "Object mapper;");
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
  it("a number is silent", async () => {
    const source = body(false, "return String.valueOf(Integer.parseInt(name));");
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
  it("Kotlin expression body with an inferred String and produces text/html", async () => {
    const source = `import org.springframework.web.bind.annotation.*\n@RestController class C {\n@GetMapping("/x", produces = ["text/html"]) fun h(@RequestParam name: String) = "<p>$name</p>"\n}\n`;
    expect(kind(of(await run(source, "K.kt"), XSS))).toBe("high/confirmed/high");
  });
  it("Kotlin expression body without produces and with markup", async () => {
    const source = `import org.springframework.web.bind.annotation.*\n@RestController class C {\n@GetMapping("/x") fun h(@RequestParam name: String) = "<p>$name</p>"\n}\n`;
    expect(kind(of(await run(source, "K.kt"), XSS))).toBe("high/confirmed/medium");
  });
  it("Kotlin: a throw is not a body, a return is (M10)", async () => {
    const thrown = `import org.springframework.web.bind.annotation.*\n@RestController class C {\n@GetMapping("/x") fun h(@RequestParam name: String): String {\nthrow IllegalArgumentException("bad $name")\n}\n}\n`;
    expect(kind(of(await run(thrown, "K.kt"), XSS))).toBe("none");
    const returned = thrown.replace(
      'throw IllegalArgumentException("bad $name")',
      'return "<b>$name</b>"',
    );
    expect(kind(of(await run(returned, "K.kt"), XSS))).toBe("high/confirmed/medium");
  });
});

describe("PG-XSS-004: writer without a content type", () => {
  it("an untraced value is low", async () => {
    expect(kind(of(await run(servlet("resp.getWriter().println(render());")), XSS))).toBe(
      "inferred",
    );
  });
  it("a field is low", async () => {
    const source = servlet("resp.getWriter().println(banner);", "String banner;");
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
  it("a JSON serialiser result is silent", async () => {
    const source = servlet("resp.getWriter().println(mapper.writeValueAsString(p));");
    expect(kind(of(await run(source), XSS))).toBe("none");
  });
  it("a content type set in only one branch is not known: low, not silent", async () => {
    const source = servlet(
      'if (p.isEmpty()) { resp.setContentType("application/json"); }\nresp.getWriter().write("<p>" + p + "</p>");',
    );
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
  it("a different content type in each branch is not known", async () => {
    const source = servlet(
      'if (p.isEmpty()) { resp.setContentType("text/html"); } else { resp.setContentType("application/json"); }\nresp.getWriter().write(p);',
    );
    expect(kind(of(await run(source), XSS))).toBe("inferred");
  });
  it("the content type does not carry from one method to the next (M18, M19)", async () => {
    const source = java(
      SERVLET,
      `void a(HttpServletRequest req, HttpServletResponse resp) throws Exception {\nresp.setContentType("application/json");\n}\nvoid b(HttpServletRequest req, HttpServletResponse resp) throws Exception {\nresp.getWriter().write("<p>" + req.getParameter("p") + "</p>");\n}`,
    );
    expect(kind(of(await run(source), XSS))).toBe("high/confirmed/medium");
  });
  it("an escaped value does not repeat 'inferred'", async () => {
    const source = servlet(
      'resp.setContentType("text/html");\nresp.getWriter().write(HtmlUtils.htmlEscape(p));',
    );
    expect(of(await run(source), XSS)[0]?.evidence.match(/inferred/g)).toHaveLength(1);
  });
});

describe("numeric names are typed (pid, getResponseCode, ...)", () => {
  const sql = (receiver: string, call: string): string =>
    `import java.sql.Statement;\nimport org.springframework.web.bind.annotation.*;\nclass Dto { String pid() { return ""; } String getResponseCode() { return ""; } }\nclass A {\nvoid h(Statement st, @ModelAttribute Dto d) throws Exception {\n${receiver}\nst.executeQuery("SELECT * FROM t WHERE a = " + ${call});\n}\n}\n`;
  const sqlFindings = async (source: string) =>
    (await run(source)).findings.filter((f) => f.ruleId === "PG-SQL-005");
  it("a request DTO's pid() stays request input", async () => {
    expect((await sqlFindings(sql("", "d.pid()")))[0]).toMatchObject({
      severity: "high",
      confidence: "high",
    });
  });
  it("a request DTO's getResponseCode() stays request input", async () => {
    expect((await sqlFindings(sql("", "d.getResponseCode()")))[0]).toMatchObject({
      severity: "high",
      confidence: "high",
    });
  });
  it("a Process's pid() is a number", async () => {
    const found = await sqlFindings(
      sql('Process p = new ProcessBuilder("ls").start();', "p.pid()"),
    );
    expect(found[0]).toMatchObject({ confidence: "low" });
    expect(found[0]?.evidence).toContain("gives a number");
  });
});

describe("PG-SSRF-002: severity, bases and guards (mutants)", () => {
  it("a fixed base keeps medium severity and low confidence (M09)", async () => {
    const found = of(
      await run(handler('rest.getForObject("https://api.example.com/users/" + p, String.class);')),
      SSRF,
    );
    expect(found[0]).toMatchObject({ severity: "medium", confidence: "low" });
    expect(found[0]?.evidence).toContain("https://api.example.com");
  });
  it("a host followed directly by request input is not a fixed base (M06)", async () => {
    const found = of(
      await run(handler('rest.getForObject("https://api.example.com" + p, String.class);')),
      SSRF,
    );
    expect(found[0]).toMatchObject({ severity: "high", confidence: "high" });
  });
  it("a negated private-address check guards the success branch (M20)", async () => {
    const source = handler(
      "InetAddress a = InetAddress.getByName(new URL(p).getHost());\nif (!a.isSiteLocalAddress()) {\nrest.getForObject(p, String.class);\n}",
    );
    expect(kind(of(await run(source), SSRF))).toBe("inferred");
  });
  it("endsWith with a file extension is not an allowlist", async () => {
    const source = handler(
      'if (!p.endsWith(".png")) { return; }\nrest.getForObject(p, String.class);',
    );
    expect(kind(of(await run(source), SSRF))).toBe("high/confirmed/high");
  });
  it("startsWith without a trailing slash is not an allowlist", async () => {
    const source = handler(
      'if (!p.startsWith("https://api.example.com")) { return; }\nrest.getForObject(p, String.class);',
    );
    expect(kind(of(await run(source), SSRF))).toBe("high/confirmed/high");
  });
  it("startsWith with a slash and endsWith with a domain are guards", async () => {
    const one = handler(
      'if (!p.startsWith("https://api.example.com/")) { return; }\nrest.getForObject(p, String.class);',
    );
    expect(kind(of(await run(one), SSRF))).toBe("inferred");
    const two = handler(
      'if (!p.endsWith(".example.com")) { return; }\nrest.getForObject(p, String.class);',
    );
    expect(kind(of(await run(two), SSRF))).toBe("inferred");
  });
  it("new URL(context, spec): an absolute spec replaces the fixed context", async () => {
    const source = handler('new URL(new URL("https://api.example.com/v1/"), p).openStream();');
    expect(kind(of(await run(source), SSRF))).toBe("high/confirmed/high");
  });
  it("UriComponentsBuilder.host(tainted) is not a fixed base", async () => {
    const source = handler(
      'URI u = UriComponentsBuilder.fromHttpUrl("https://x.example.com/a").host(p).build().toUri();\nrest.getForObject(u, String.class);',
    );
    expect(kind(of(await run(source), SSRF))).toBe("high/suspected/high");
  });
});

describe("web rules: partial forms", () => {
  it("a Kotlin extension function that writes to the response is reported as unsupported", async () => {
    const source = `import javax.servlet.http.HttpServletResponse\nfun HttpServletResponse.page(name: String) {\nwriter.write("<p>" + name + "</p>")\n}\n`;
    expect((await run(source, "K.kt")).unsupportedForms).toContain("extension function");
  });
});
