import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { scanSourceCode } from "../scan-source.js";
import { analyzeJsp, analyzeThymeleaf, type ModelSource } from "./templates.js";

function kind(findings: RawSourceFinding[]): string {
  if (findings.length === 0) return "none";
  const finding = findings[0] as RawSourceFinding;
  if (finding.confidence === "low") return "inferred";
  return `${finding.severity}/${finding.status}/${finding.confidence}`;
}

describe("PG-XSS-004: JSP", () => {
  const cases: Array<[string, string, string]> = [
    [
      "a request parameter in <%= %>",
      '<p><%= request.getParameter("q") %></p>',
      "high/confirmed/high",
    ],
    [
      "a scriptlet variable in <%= %>",
      '<% String name = request.getParameter("n"); %>\n<p><%= name %></p>',
      "high/suspected/high",
    ],
    [
      "out.println of a concatenation",
      '<% out.println("<b>" + request.getParameter("x") + "</b>"); %>',
      "high/confirmed/high",
    ],
    ["${param.x} in template text", "<p>Hello ${param.name}</p>", "high/confirmed/high"],
    ["${param.x} in an attribute", '<input value="${param.name}">', "high/confirmed/high"],
    ["header in EL", "<p>${header['User-Agent']}</p>", "high/confirmed/high"],
    ["c:out escapes", '<c:out value="${param.q}"/>', "none"],
    ["fn:escapeXml escapes", "<p>${fn:escapeXml(param.q)}</p>", "none"],
    [
      'c:out with escapeXml="false"',
      '<c:out value="${param.q}" escapeXml="false"/>',
      "high/confirmed/high",
    ],
    [
      "a helper that escapes",
      '<%= StringEscapeUtils.escapeHtml4(request.getParameter("q")) %>',
      "inferred",
    ],
    [
      "a variable escaped before it is printed",
      '<% String q = request.getParameter("q"); q = HtmlUtils.htmlEscape(q); %><%= q %>',
      "inferred",
    ],
    ["a literal in <%= %>", '<%= "hello" %>', "none"],
    ["a JSP comment", "<%-- ${param.q} --%>", "none"],
    ["an escaped EL start", "<p>\\${param.q}</p>", "none"],
    ["isELIgnored", '<%@ page isELIgnored="true" %>\n<p>${param.q}</p>', "none"],
    ["a bean property in raw output", "<p>${user.name}</p>", "inferred"],
    [
      "c:set from a parameter, then raw EL",
      '<c:set var="q" value="${param.q}"/>\n<p>${q}</p>',
      "high/suspected/high",
    ],
    [
      "an HTML comment still runs scriptlets",
      '<!-- <%= request.getParameter("q") %> -->',
      "high/confirmed/high",
    ],
    ["an HTML comment still runs EL", "<!-- ${param.q} -->", "high/confirmed/high"],
    [
      "a JSP that sends JSON is not HTML",
      '<%@ page contentType="application/json" %>\n<%= request.getParameter("q") %>',
      "none",
    ],
    [
      "fn:escapeXml in one branch of a ternary",
      "<p>${empty x ? fn:escapeXml(param.q) : param.q}</p>",
      "high/confirmed/high",
    ],
    ["fn:escapeXml around the whole expression", "<p>${fn:escapeXml(param.q)}</p>", "none"],
    ["a taglib tag attribute is not output", '<c:if test="${param.q == 1}">x</c:if>', "none"],
  ];
  for (const [name, source, expected] of cases) {
    it(name, () => {
      expect(kind(analyzeJsp(source, "a.jsp").findings)).toBe(expected);
    });
  }

  it("reports the line of each finding", () => {
    const { findings } = analyzeJsp(
      '<html>\n<body>\n<%= request.getParameter("q") %>\n</body>',
      "a.jsp",
    );
    expect(findings.map((finding) => finding.line)).toEqual([3]);
  });
});

describe("PG-XSS-004: Thymeleaf", () => {
  const model = new Map<string, ModelSource[]>([
    ["comment", [{ path: "C.java", line: 12, views: ["a"] }]],
    ["note", [{ path: "D.java", line: 3, views: [] }]],
    ["title", [{ path: "E.java", line: 9, views: ["search"] }]],
  ]);
  const cases: Array<[string, string, string]> = [
    ["th:text escapes", '<p th:text="${param.q}"></p>', "none"],
    [
      "th:utext with a request parameter",
      '<p th:utext="${param.q[0]}"></p>',
      "high/confirmed/high",
    ],
    [
      "th:utext with a model value set from request input",
      '<p th:utext="${comment}"></p>',
      "high/suspected/medium",
    ],
    [
      "th:utext with a property of such a model value",
      '<p th:utext="${comment.body}"></p>',
      "high/suspected/medium",
    ],
    ["th:utext with another model value", '<p th:utext="${article}"></p>', "inferred"],
    ["th:utext with a message key", '<p th:utext="#{welcome.html}"></p>', "none"],
    ["th:utext with a literal", `<p th:utext="'<b>hi</b>'"></p>`, "none"],
    [
      "th:utext with an escaping helper",
      '<p th:utext="${#strings.escapeXml(comment)}"></p>',
      "inferred",
    ],
    ["inline unescaped output", "<p>[(${comment})]</p>", "high/suspected/medium"],
    ["inline escaped output", "<p>[[${comment}]]</p>", "none"],
    ["data- prefixed attribute", '<p data-th-utext="${param.q}"></p>', "high/confirmed/high"],
    ["a comment", '<!-- <p th:utext="${param.q}"></p> -->\n<p th:text="${x}"></p>', "none"],
    [
      "a model value matched by name only (the view is not resolvable)",
      '<p th:utext="${note}"></p>',
      "inferred",
    ],
    [
      "a model value set by a handler that returns another view",
      '<p th:utext="${title}"></p>',
      "inferred",
    ],
    [
      "an escape helper next to a request parameter",
      '<p th:utext="${#strings.escapeXml(a) + param.q}"></p>',
      "high/confirmed/high",
    ],
    [
      "a Spring HtmlUtils call on a request parameter",
      '<p th:utext="${@htmlUtils.htmlEscape(param.q)}"></p>',
      "inferred",
    ],
    [
      "a helper that is not an escaper",
      '<p th:utext="${@util.shorten(param.q)}"></p>',
      "high/confirmed/high",
    ],
    [
      "a block that only Thymeleaf runs",
      '<!--/*/ <p th:utext="${param.q}"></p> /*/-->',
      "high/confirmed/high",
    ],
  ];
  for (const [name, source, expected] of cases) {
    it(name, () => {
      expect(kind(analyzeThymeleaf(source, "a.html", model).findings)).toBe(expected);
    });
  }
});

describe("scanSourceCode with templates", () => {
  const roots: string[] = [];
  function project(files: Record<string, string>): string {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-tpl-")));
    roots.push(root);
    for (const [name, content] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      writeFileSync(path.join(root, name), content);
    }
    return root;
  }
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });
  const xss = (output: Awaited<ReturnType<typeof scanSourceCode>>) =>
    output.findings.filter((finding) => finding.ruleId === "PG-XSS-004");

  it("reads a JSP in a project with a Maven manifest and no Java file", async () => {
    const root = project({
      "pom.xml": "<project/>\n",
      "web/index.jsp": '<p><%= request.getParameter("q") %></p>\n',
    });
    const output = await scanSourceCode(root);
    expect(xss(output).map((finding) => finding.location.path)).toEqual(["web/index.jsp"]);
    expect(output.coverage.find((item) => item.area === "source:jvm-templates")).toMatchObject({
      status: "completed",
      ruleIds: ["PG-XSS-004"],
    });
  });

  it("matches a Thymeleaf model value to the controller that fills it from the request", async () => {
    const root = project({
      "src/C.java": `import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
@Controller
class C {
  @GetMapping("/c") String c(@RequestParam String comment, Model model) {
    model.addAttribute("comment", comment);
    model.addAttribute("title", "Comments");
    return "comment";
  }
}
`,
      "src/main/resources/templates/comment.html":
        '<html xmlns:th="http://www.thymeleaf.org"><p th:utext="${comment}"></p><h1 th:utext="${title}"></h1><p th:text="${comment}"></p></html>\n',
    });
    const output = await scanSourceCode(root);
    const found = xss(output).filter((finding) => (finding.location.path ?? "").endsWith(".html"));
    expect(found).toHaveLength(2);
    const [byModel, other] = found;
    expect(byModel).toMatchObject({ severity: "high", confidence: "medium", status: "suspected" });
    expect(byModel?.evidence).toContain("C.java:7");
    expect(other).toMatchObject({ confidence: "low" });
  });

  it("reads no template in a project that is not a Java or Kotlin one", async () => {
    const root = project({
      "package.json": "{}\n",
      "app.js": "console.log(1);\n",
      "views/index.mustache": "<p>{{name}}</p>\n",
      "views/page.vm": "<p>$name</p>\n",
      "public/index.html": '<html xmlns:th="x"><p th:utext="${param.q}"></p></html>\n',
    });
    const output = await scanSourceCode(root);
    expect(xss(output)).toEqual([]);
    expect(
      output.coverage.filter((item) => /^source:(?:jvm-templates|template:)/.test(item.area)),
    ).toEqual([]);
  });

  it("reads a JSP-only directory with no Java file and no manifest", async () => {
    const root = project({ "web/index.jsp": '<p><%= request.getParameter("q") %></p>\n' });
    const output = await scanSourceCode(root);
    expect(xss(output).map((finding) => finding.location.path)).toEqual(["web/index.jsp"]);
    expect(output.coverage.find((item) => item.area === "source:jvm-templates")).toBeDefined();
  });

  it("honours the exclude patterns for template engine files", async () => {
    const root = project({
      "A.java": "class A {}\n",
      "legacy/page.ftl": "<p>${x}</p>\n",
    });
    const output = await scanSourceCode(root, {
      projectConfig: { version: 1, exclude: ["legacy"], testDirectories: [], suppressions: [] },
    });
    expect(output.coverage.some((item) => item.area.startsWith("source:template:"))).toBe(false);
  });

  it("links a model value only to the template of the handler that sets it", async () => {
    const controller = (
      view: string,
      value: string,
    ): string => `import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
@Controller
class C${view} {
  @GetMapping("/${view}") String ${view}(@RequestParam String q, Model model) {
    model.addAttribute("title", ${value});
    return "${view}";
  }
}
`;
    const root = project({
      "src/Search.java": controller("search", "q"),
      "src/About.java": controller("about", '"About"'),
      "src/main/resources/templates/search.html":
        '<html xmlns:th="http://www.thymeleaf.org"><h1 th:utext="${title}"></h1></html>\n',
      "src/main/resources/templates/about.html":
        '<html xmlns:th="http://www.thymeleaf.org"><h1 th:utext="${title}"></h1></html>\n',
    });
    const output = await scanSourceCode(root);
    const byPath = new Map(xss(output).map((finding) => [finding.location.path, finding]));
    expect(byPath.get("src/main/resources/templates/search.html")).toMatchObject({
      confidence: "medium",
      severity: "high",
    });
    expect(byPath.get("src/main/resources/templates/about.html")).toMatchObject({
      confidence: "low",
    });
  });

  it("does not read an HTML file that is not a Thymeleaf template", async () => {
    const root = project({
      "A.java": "class A {}\n",
      "public/index.html": "<html><body>${not a template} [( x )]</body></html>\n",
    });
    const output = await scanSourceCode(root);
    expect(xss(output)).toEqual([]);
    expect(output.coverage.some((item) => item.area === "source:jvm-templates")).toBe(false);
  });

  it("reports template engines it does not read as partial coverage", async () => {
    const root = project({
      "A.java": "import freemarker.template.Configuration;\nclass A {}\n",
      "src/main/resources/templates/page.ftl": "<p>${user.name}</p>\n",
      "src/main/resources/templates/mail.vm": "<p>$user.name</p>\n",
    });
    const output = await scanSourceCode(root);
    const freemarker = output.coverage.find((item) => item.area === "source:template:freemarker");
    expect(freemarker).toMatchObject({ status: "partial", ruleIds: ["PG-XSS-004"] });
    expect(freemarker?.note).toContain("not a safe result");
    expect(output.coverage.find((item) => item.area === "source:template:velocity")).toMatchObject({
      status: "partial",
    });
  });

  it("marks the language area partial when a file calls through reflection next to HTTP APIs (#328)", async () => {
    const root = project({
      "A.java": `import java.net.http.HttpClient;
class A {
  Object f(String name) throws Exception {
    return Class.forName(name).getMethod("run").invoke(null);
  }
}
`,
    });
    const output = await scanSourceCode(root);
    const entry = output.coverage.find((item) => item.area === "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("reflection");
  });

  it("counts a file whose only syntax error is a MISSING node as partial (#324)", async () => {
    const root = project({
      "A.java": "class A {\n  void f() {\n    int x = 1\n  }\n}\n",
    });
    const output = await scanSourceCode(root);
    const entry = output.coverage.find((item) => item.area === "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("syntax errors");
  });
});
