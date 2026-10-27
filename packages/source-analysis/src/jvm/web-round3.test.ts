import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { scanSourceCode } from "../scan-source.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";
import { analyzeThymeleaf, type ModelSource } from "./templates.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, file = "A.java") {
  const language = file.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, file, language);
  } finally {
    outcome.dispose();
  }
}

const XSS = "PG-XSS-004";
const SSRF = "PG-SSRF-002";
const of = (findings: RawSourceFinding[], ruleId: string) =>
  findings.filter((finding) => finding.ruleId === ruleId);
function kind(findings: RawSourceFinding[]): string {
  const first = findings[0];
  if (first === undefined) return "none";
  if (first.confidence === "low") return "inferred";
  return `${first.severity}/${first.status}/${first.confidence}`;
}

const SPRING =
  "import org.springframework.web.bind.annotation.*;\nimport org.springframework.web.client.RestTemplate;\nimport org.springframework.web.util.*;\nimport java.net.*;\nimport java.util.*;\n";
const handler = (body: string): string =>
  `${SPRING}\nclass A {\nRestTemplate rest = new RestTemplate();\n@GetMapping("/x") void h(@RequestParam String p) throws Exception {\n${body}\n}\n}\n`;
const SERVLET =
  "import javax.servlet.http.*;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nimport com.google.gson.Gson;\n";
const servlet = (body: string): string =>
  `${SERVLET}\nclass A {\nObjectMapper mapper;\nGson gson;\nvoid h(HttpServletRequest req, HttpServletResponse resp) throws Exception {\nString p = req.getParameter("p");\n${body}\n}\n}\n`;

describe("Kotlin extension functions", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });
  const scan = async (source: string) => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-ext-")));
    roots.push(root);
    mkdirSync(root, { recursive: true });
    writeFileSync(path.join(root, "App.kt"), source);
    const output = await scanSourceCode(root);
    return output.coverage.find((item) => item.area === "source:kotlin");
  };
  it("a Ktor application module with respondText stays completed", async () => {
    const entry = await scan(
      `import io.ktor.server.application.*\nimport io.ktor.server.response.*\nimport io.ktor.server.routing.*\nfun Application.module() {\n  routing { get("/") { call.respondText("Hello") } }\n}\n`,
    );
    expect(entry?.status).toBe("completed");
  });
  it("a Ktor Route extension that writes through call stays completed", async () => {
    const entry = await scan(
      `import io.ktor.server.application.*\nimport io.ktor.server.response.*\nimport io.ktor.server.routing.*\nfun Route.page() {\n  get("/p") { call.response.header("X", "1"); call.respondText("ok") }\n}\n`,
    );
    expect(entry?.status).toBe("completed");
  });
  it("an HttpServletResponse extension is reported as unsupported", async () => {
    const source = `import javax.servlet.http.HttpServletResponse\nfun HttpServletResponse.html(s: String) {\n  contentType = "text/html"\n  writer.write(s)\n}\n`;
    expect((await run(source, "K.kt")).unsupportedForms).toContain("extension function");
    expect((await scan(source))?.status).toBe("partial");
  });
  it("an implicit writer in an extension of another type is unsupported", async () => {
    const source = `class Page\nfun Page.render(w: java.io.Writer) {\n  writer.write("x")\n}\n`;
    expect((await run(source, "K.kt")).unsupportedForms).toContain("extension function");
  });
});

describe("JSON serialisers", () => {
  it("Jackson output with no content type is JSON: silent", async () => {
    const found = of(
      (await run(servlet("resp.getWriter().write(mapper.writeValueAsString(p));"))).findings,
      XSS,
    );
    expect(kind(found)).toBe("none");
  });
  it("Jackson output written as text/html is low (it does not escape <)", async () => {
    const source = servlet(
      'resp.setContentType("text/html");\nresp.getWriter().write(mapper.writeValueAsString(p));',
    );
    expect(kind(of((await run(source)).findings, XSS))).toBe("inferred");
  });
  it("Gson output may stay silent as text/html", async () => {
    const source = servlet(
      'resp.setContentType("text/html");\nresp.getWriter().write(gson.toJson(p));',
    );
    expect(kind(of((await run(source)).findings, XSS))).toBe("none");
  });
  it("a project-defined toJson is not a serialiser", async () => {
    const source = servlet('resp.setContentType("text/html");\nresp.getWriter().write(toJson(p));');
    expect(kind(of((await run(source)).findings, XSS))).toBe("inferred");
  });
  it("a serialised request value stays request input for SQL", async () => {
    const source = `import java.sql.Statement;\nimport com.fasterxml.jackson.databind.ObjectMapper;\nimport javax.servlet.http.*;\nclass A {\nObjectMapper mapper;\nvoid h(Statement st, HttpServletRequest req) throws Exception {\nst.executeQuery("SELECT * FROM t WHERE a = '" + mapper.writeValueAsString(req.getParameter("p")) + "'");\n}\n}\n`;
    const found = (await run(source)).findings.filter((f) => f.ruleId === "PG-SQL-005");
    expect(found[0]).toMatchObject({ severity: "high", confidence: "high" });
  });
});

describe("SSRF builders and guards", () => {
  it("UriComponentsBuilder.newInstance().host(tainted) is high", async () => {
    const source = handler(
      'URI u = UriComponentsBuilder.newInstance().scheme("https").host(p).path("/a").build().toUri();\nrest.getForObject(u, String.class);',
    );
    expect(kind(of((await run(source)).findings, SSRF))).toBe("high/suspected/high");
  });
  it("UriComponentsBuilder.newInstance().port(tainted) is high", async () => {
    const source = handler(
      'URI u = UriComponentsBuilder.newInstance().scheme("https").host("a.example.com").port(p).build().toUri();\nrest.getForObject(u, String.class);',
    );
    expect(kind(of((await run(source)).findings, SSRF))).toBe("high/suspected/high");
  });
  it("endsWith without a leading dot is not an allowlist", async () => {
    const source = handler(
      'if (!new URL(p).getHost().endsWith("example.com")) { return; }\nrest.getForObject(p, String.class);',
    );
    expect(kind(of((await run(source)).findings, SSRF))).toBe("high/confirmed/high");
  });
  it("endsWith with a leading dot is a guard", async () => {
    const source = handler(
      'if (!new URL(p).getHost().endsWith(".example.com")) { return; }\nrest.getForObject(p, String.class);',
    );
    expect(kind(of((await run(source)).findings, SSRF))).toBe("inferred");
  });
});

describe("typed numeric receivers, each condition alone (N08, N09)", () => {
  const sql = (decl: string, call: string): string =>
    `import java.sql.Statement;\nimport javax.servlet.http.*;\nclass Dto { String pid() { return ""; } }\nclass A {\nvoid h(Statement st, HttpServletRequest req) throws Exception {\n${decl}\nst.executeQuery("SELECT " + ${call});\n}\n}\n`;
  const sqlFinding = async (source: string) =>
    (await run(source)).findings.filter((f) => f.ruleId === "PG-SQL-005")[0];
  it("a Process built from request input does not give a number (N08)", async () => {
    const found = await sqlFinding(
      sql('Process p = Runtime.getRuntime().exec(req.getParameter("c"));', "p.pid()"),
    );
    expect(found).toMatchObject({ severity: "high", confidence: "high" });
  });
  it("a value of another type with a pid() does not give a number (N09)", async () => {
    const found = await sqlFinding(sql("Dto d = new Dto();", "d.pid()"));
    expect(found?.evidence ?? "").not.toContain("gives a number");
  });
});

describe("model attribute views (N07, N14, N15)", () => {
  const controller = (members: string): string =>
    `import org.springframework.stereotype.Controller;\nimport org.springframework.ui.Model;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.web.servlet.ModelAndView;\n@Controller\nclass C {\n${members}\n}\n`;
  it("a redirect is not a view (N07)", async () => {
    const source = controller(
      '@GetMapping("/a") String a(@RequestParam String q, Model model) { model.addAttribute("title", q); return "redirect:/home"; }',
    );
    expect((await run(source)).modelAttributes[0]?.views).toEqual([]);
  });
  it("views do not carry from one method to the next (N14)", async () => {
    const source = controller(
      '@GetMapping("/a") String a(Model model) { return "first"; }\n@GetMapping("/b") String b(@RequestParam String q, Model model) { model.addAttribute("title", q); return "second"; }',
    );
    expect((await run(source)).modelAttributes[0]?.views).toEqual(["second"]);
  });
  it("the ModelAndView constructor names the view (N15)", async () => {
    const source = controller(
      '@GetMapping("/a") ModelAndView a(@RequestParam String q) { return new ModelAndView("search", "title", q); }',
    );
    const attributes = (await run(source)).modelAttributes;
    expect(attributes[0]).toMatchObject({ name: "title", tainted: true, views: ["search"] });
  });
  it("a name-only match says where the attribute may be set (N06)", () => {
    const model = new Map<string, ModelSource[]>([
      ["note", [{ path: "D.java", line: 3, views: [] }]],
    ]);
    const { findings } = analyzeThymeleaf('<p th:utext="${note}"></p>', "x.html", model);
    expect(findings[0]).toMatchObject({ confidence: "low" });
    expect(findings[0]?.evidence).toContain("D.java:3");
  });
});

describe("ResponseEntity with an HTML content type (M18)", () => {
  it("is reported once", async () => {
    const source = `import org.springframework.web.bind.annotation.*;\nimport org.springframework.http.*;\n@RestController\nclass A {\n@GetMapping("/x") ResponseEntity<String> h(@RequestParam String name) {\nreturn ResponseEntity.ok()\n.contentType(MediaType.TEXT_HTML)\n.body("<p>" + name + "</p>");\n}\n}\n`;
    expect(of((await run(source)).findings, XSS)).toHaveLength(1);
  });
});
