import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { scanSourceCode } from "../scan-source.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

/**
 * Kotlin forms that used to give no finding and no partial coverage (#339): implicit receivers in
 * extension functions, kotlinx.html `unsafe`, WebFlux `bodyValue`, and the false partials.
 */

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, file = "K.kt") {
  const language = file.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, file, language);
  } finally {
    outcome.dispose();
  }
}

const xss = async (source: string, file = "K.kt"): Promise<RawSourceFinding[]> =>
  (await run(source, file)).findings.filter((finding) => finding.ruleId === "PG-XSS-004");

/** Words for the verdict: severity/status/confidence of the first XSS finding, or `none`. */
const verdict = (findings: RawSourceFinding[]): string => {
  const first = findings[0];
  return first === undefined ? "none" : `${first.severity}/${first.status}/${first.confidence}`;
};

const KTOR =
  "import io.ktor.http.*\nimport io.ktor.server.application.*\nimport io.ktor.server.response.*\nimport io.ktor.server.html.*\nimport kotlinx.html.*\n";
const FLUX =
  "import org.springframework.http.MediaType\nimport org.springframework.web.reactive.function.server.*\n";

describe("implicit receiver of an ApplicationCall extension (#339 item 1)", () => {
  it("implicit parameters and implicit respondText", async () => {
    const source = `${KTOR}suspend fun ApplicationCall.greet() {\n  val n = parameters["n"]\n  respondText("<b>$n</b>", ContentType.Text.Html)\n}\n`;
    const found = await xss(source);
    expect(verdict(found)).toBe("high/suspected/high");
    expect(found[0]?.evidence).toContain("this.parameters");
  });
  it("implicit request.queryParameters", async () => {
    const source = `${KTOR}suspend fun ApplicationCall.greet() {\n  val n = request.queryParameters["n"]\n  respondText("<b>$n</b>", ContentType.Text.Html)\n}\n`;
    expect(verdict(await xss(source))).toBe("high/suspected/high");
  });
  it("this.parameters and an explicit call.respondText in the same extension", async () => {
    const source = `${KTOR}suspend fun ApplicationCall.greet() {\n  val n = this.parameters["n"]\n  this.respondText("<b>$n</b>", ContentType.Text.Html)\n}\n`;
    expect(verdict(await xss(source))).toBe("high/suspected/high");
  });
  it("plain text is not XSS", async () => {
    const source = `${KTOR}suspend fun ApplicationCall.greet() {\n  val n = parameters["n"]\n  respondText("<b>$n</b>")\n}\n`;
    expect(verdict(await xss(source))).toBe("none");
  });
  it("a local named parameters is the local, not the request", async () => {
    const source = `${KTOR}suspend fun ApplicationCall.greet() {\n  val parameters = mapOf("n" to "x")\n  respondText("<b>\${parameters["n"]}</b>", ContentType.Text.Html)\n}\n`;
    expect(verdict(await xss(source))).not.toBe("high/suspected/high");
  });
  it("a function of the file with the name of a request member is that function", async () => {
    const source = `${KTOR}fun parameters(): String = "fixed"\nsuspend fun ApplicationCall.greet() {\n  respondText("<b>" + parameters() + "</b>", ContentType.Text.Html)\n}\n`;
    expect(verdict(await xss(source))).not.toBe("high/suspected/high");
  });
  it("a Route extension (receiver is not a request) is unchanged", async () => {
    const source = `${KTOR}import io.ktor.server.routing.*\nfun Route.page() {\n  get("/p") { call.respondText("<b>" + call.parameters["n"] + "</b>", ContentType.Text.Html) }\n}\n`;
    const analysis = await run(source);
    expect(verdict(analysis.findings)).toBe("high/confirmed/high");
    expect(analysis.unsupportedForms).not.toContain("extension function");
  });
});

describe("kotlinx.html unsafe (#339 item 2)", () => {
  const route = (body: string): string =>
    `${KTOR}suspend fun ApplicationCall.profile() {\n  val bio = request.queryParameters["bio"] ?: ""\n  ${body}\n}\n`;
  it("+bio inside unsafe is raw output", async () => {
    const found = await xss(route("respondHtml { body { unsafe { +bio } } }"));
    expect(verdict(found)).toBe("high/suspected/high");
    expect(found[0]?.evidence).toContain("unsafe");
  });
  it("raw(bio) inside unsafe is raw output", async () => {
    expect(verdict(await xss(route("respondHtml { body { unsafe { raw(bio) } } }")))).toBe(
      "high/suspected/high",
    );
  });
  it("with an explicit call receiver", async () => {
    const source = `${KTOR}fun Application.module() {\n  routing { get("/") {\n    val bio = call.request.queryParameters["bio"] ?: ""\n    call.respondHtml { body { unsafe { +bio } } }\n  } }\n}\n`;
    expect(verdict(await xss(source))).toBe("high/suspected/high");
  });
  it("+bio outside unsafe is escaped text", async () => {
    expect(verdict(await xss(route("respondHtml { body { p { +bio } } }")))).toBe("none");
  });
  it("a fixed string inside unsafe is not a finding", async () => {
    expect(verdict(await xss(route('respondHtml { body { unsafe { +"<b>hi</b>" } } }')))).toBe(
      "none",
    );
  });
  it("a value that is escaped first is not request input", async () => {
    const source = route("respondHtml { body { unsafe { +HtmlUtils.htmlEscape(bio) } } }");
    expect(verdict(await xss(source))).not.toBe("high/suspected/high");
  });
  it("unsafe in an unrelated lambda does not make +x elsewhere a sink", async () => {
    const source = route('respondHtml { body { unsafe { +"x" }; p { +bio } } }');
    expect(verdict(await xss(source))).toBe("none");
  });
  it("a unary plus on a number still gives no text", async () => {
    const source = `fun f(call: io.ktor.server.application.ApplicationCall): Int {\n  val n = call.parameters["n"]!!.toInt()\n  return +n\n}\n`;
    expect(verdict(await xss(source))).toBe("none");
  });
});

describe("WebFlux ServerRequest extensions (#339 item 3)", () => {
  const ext = (body: string): string =>
    `${FLUX}suspend fun ServerRequest.greet(): ServerResponse {\n  val n = queryParam("n").orElse("x")\n  ${body}\n}\n`;
  it("an HTML content type makes bodyValueAndAwait a sink", async () => {
    const source = ext(
      'return ServerResponse.ok().contentType(MediaType.TEXT_HTML).bodyValueAndAwait("<b>$n</b>")',
    );
    const found = await xss(source);
    expect(verdict(found)).toBe("high/suspected/high");
    expect(found[0]?.evidence).toContain("this.queryParam");
  });
  it("bodyValue with an HTML content type", async () => {
    const source = ext(
      'return ServerResponse.ok().contentType(MediaType.TEXT_HTML).bodyValue("<b>$n</b>")',
    );
    expect(verdict(await xss(source))).toBe("high/suspected/high");
  });
  it("the Kotlin html() builder", async () => {
    const source = ext('return ServerResponse.ok().html().bodyValueAndAwait("<b>$n</b>")');
    expect(verdict(await xss(source))).toBe("high/suspected/high");
  });
  it("a JSON content type is not XSS", async () => {
    const source = ext(
      'return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValueAndAwait("<b>$n</b>")',
    );
    expect(verdict(await xss(source))).toBe("none");
    expect(
      verdict(await xss(ext('return ServerResponse.ok().json().bodyValueAndAwait("<b>$n</b>")'))),
    ).toBe("none");
  });
  it("no content type that is known: medium for markup, low for plain text, never silent", async () => {
    const markup = await xss(ext('return ServerResponse.ok().bodyValueAndAwait("<b>$n</b>")'));
    expect(verdict(markup)).toBe("high/suspected/medium");
    expect(markup[0]?.evidence).toContain("no content type set");
    const plain = await xss(ext("return ServerResponse.ok().bodyValueAndAwait(n)"));
    expect(plain).toHaveLength(1);
    expect(plain[0]?.confidence).toBe("low");
  });
  it("a content type that is not one value is low", async () => {
    const source = ext(
      'val type = if (n.isEmpty()) MediaType.TEXT_HTML else MediaType.APPLICATION_JSON\n  return ServerResponse.ok().contentType(type).bodyValueAndAwait("<b>$n</b>")',
    );
    const found = await xss(source);
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe("low");
  });
  it("a typed value that is not a String is a serialised object", async () => {
    const source = `${FLUX}suspend fun ServerRequest.greet(): ServerResponse {\n  val user: User = awaitBody()\n  return ServerResponse.ok().bodyValueAndAwait(user)\n}\n`;
    expect(verdict(await xss(source))).toBe("none");
  });
  it("a WebClient request body is not a response body", async () => {
    const source = `${FLUX}import org.springframework.web.reactive.function.client.WebClient\nsuspend fun ServerRequest.forward(client: WebClient) {\n  val n = queryParam("n").orElse("x")\n  client.post().uri("https://api.example.com/x").bodyValue("<b>$n</b>")\n}\n`;
    expect(await xss(source)).toHaveLength(0);
  });
  it("implicit pathVariable and awaitBody are request input", async () => {
    const path = `${FLUX}suspend fun ServerRequest.a(): ServerResponse {\n  val n = pathVariable("n")\n  return ServerResponse.ok().html().bodyValueAndAwait("<b>$n</b>")\n}\n`;
    expect(verdict(await xss(path))).toBe("high/suspected/high");
    const body = `${FLUX}suspend fun ServerRequest.b(): ServerResponse {\n  val n = awaitBody<String>()\n  return ServerResponse.ok().html().bodyValueAndAwait("<b>$n</b>")\n}\n`;
    expect(verdict(await xss(body))).toBe("high/suspected/high");
  });
  it("a handler that takes the request as a parameter", async () => {
    const source = `${FLUX}suspend fun greet(request: ServerRequest): ServerResponse {\n  val n = request.queryParam("n").orElse("x")\n  return ServerResponse.ok().html().bodyValueAndAwait("<b>$n</b>")\n}\n`;
    expect(verdict(await xss(source))).toBe("high/suspected/high");
  });
  it("Java: ServerResponse.ok().contentType(TEXT_HTML).bodyValue is still found", async () => {
    const source = `import org.springframework.http.MediaType;\nimport org.springframework.web.reactive.function.server.*;\nclass A {\nServerResponse h(ServerRequest request) {\nString n = request.queryParam("n").orElse("x");\nreturn ServerResponse.ok().contentType(MediaType.TEXT_HTML).bodyValue("<b>" + n + "</b>");\n}\n}\n`;
    expect(verdict(await xss(source, "A.java"))).toBe("high/suspected/high");
  });
});

describe("implicit-this extensions: no false partial, no silent write (#339)", () => {
  const unsupported = async (source: string) => (await run(source)).unsupportedForms;

  it("a local named writer is not the receiver's (List<String>.csv)", async () => {
    const source = `fun List<String>.csv(): String {\n  val writer = java.io.StringWriter()\n  forEach { writer.write(it) }\n  return writer.toString()\n}\n`;
    expect(await unsupported(source)).not.toContain("extension function");
  });
  it("a parameter named writer is not the receiver's", async () => {
    const source = `class Page\nfun Page.render(writer: java.io.Writer) {\n  writer.write("x")\n}\n`;
    expect(await unsupported(source)).not.toContain("extension function");
  });
  it("a field named writer is not the receiver's", async () => {
    const source = `class Page\nval writer = java.io.StringWriter()\nfun Page.render() {\n  writer.write("x")\n}\n`;
    expect(await unsupported(source)).not.toContain("extension function");
  });
  it("a servlet-typed extension with no writes is not partial (the receiver type alone is not enough)", async () => {
    const source = `import javax.servlet.http.HttpServletResponse\nfun HttpServletResponse.ok() {\n  status = 200\n}\nfun javax.servlet.http.HttpServletRequest.id(): String = getParameter("id") ?: ""\n`;
    expect(await unsupported(source)).not.toContain("extension function");
  });
  it("a URL-typed extension with no calls on it is not partial", async () => {
    const source = `import java.net.URL\nfun URL.label(): String = "url"\n`;
    expect(await unsupported(source)).not.toContain("extension function");
  });
  it("an implicit writer in an extension of another type is still partial (an implicit write alone is enough)", async () => {
    const source = `class Page\nfun Page.render() {\n  writer.write("x")\n}\n`;
    expect(await unsupported(source)).toContain("extension function");
  });
  it("an implicit getWriter() / getOutputStream() in an extension of another type is partial", async () => {
    expect(
      await unsupported(`class Page\nfun Page.render() {\n  getWriter().write("x")\n}\n`),
    ).toContain("extension function");
    expect(
      await unsupported(`class Page\nfun Page.render() {\n  getOutputStream().write(1)\n}\n`),
    ).toContain("extension function");
  });
  it("an implicit writer nested in a lambda, a condition and a template is still found", async () => {
    expect(
      await unsupported(
        `class Page\nfun Page.render(x: Boolean) {\n  if (x) { listOf(1).forEach { writer.write("x") } }\n}\n`,
      ),
    ).toContain("extension function");
    expect(
      await unsupported(`class Page\nfun Page.render(): String {\n  return "a \${writer}"\n}\n`),
    ).toContain("extension function");
  });
  it("a real implicit write in a servlet-typed extension is found, not lost", async () => {
    const source = `import javax.servlet.http.HttpServletResponse\nfun HttpServletResponse.page(name: String) {\n  contentType = "text/html"\n  writer.write("<p>" + name + "</p>")\n}\n`;
    const analysis = await run(source);
    expect(analysis.findings.filter((f) => f.ruleId === "PG-XSS-004")).toHaveLength(1);
    expect(analysis.unsupportedForms).not.toContain("extension function");
  });
  it("an implicit write in a servlet extension of request input is a finding", async () => {
    const source = `import javax.servlet.http.HttpServletResponse\nimport javax.servlet.http.HttpServletRequest\nfun HttpServletResponse.page(req: HttpServletRequest) {\n  contentType = "text/html"\n  getWriter().println("<p>" + req.getParameter("n") + "</p>")\n}\n`;
    expect(verdict(await xss(source))).toBe("high/confirmed/high");
  });
  it("a JSON content type set on the implicit response is not XSS", async () => {
    const source = `import javax.servlet.http.HttpServletResponse\nimport javax.servlet.http.HttpServletRequest\nfun HttpServletResponse.page(req: HttpServletRequest) {\n  setContentType("application/json")\n  writer.write(req.getParameter("n"))\n}\n`;
    expect(verdict(await xss(source))).toBe("none");
  });
  it("a bare call that opens a URL in an extension on URL is reported as not followed", async () => {
    const source = `import java.net.URL\nfun URL.fetch(): String = openStream().readBytes().decodeToString()\n`;
    expect(await unsupported(source)).toContain("extension function");
  });
  it("a Ktor Application.module extension stays complete", async () => {
    const source = `import io.ktor.server.application.*\nimport io.ktor.server.response.*\nimport io.ktor.server.routing.*\nfun Application.module() {\n  routing { get("/") { call.respondText("Hello") } }\n}\n`;
    expect(await unsupported(source)).not.toContain("extension function");
  });
  it("very deep nesting in an extension is reported, never silent", async () => {
    const depth = 300;
    const source = `class Page\nfun Page.render(x: Boolean) {\n${"if (x) {\n".repeat(depth)}writer.write("x")\n${"}\n".repeat(depth)}}\n`;
    const analysis = await run(source);
    expect(analysis.unsupportedForms.includes("extension function") || analysis.incomplete).toBe(
      true,
    );
  });
});

describe("partial coverage through a scan", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });
  const status = async (source: string) => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-xss-ext-")));
    roots.push(root);
    mkdirSync(root, { recursive: true });
    writeFileSync(path.join(root, "App.kt"), source);
    const output = await scanSourceCode(root);
    return output.coverage.find((item) => item.area === "source:kotlin")?.status;
  };
  it("List<String>.csv() with a local writer stays completed", async () => {
    expect(
      await status(
        `fun List<String>.csv(): String {\n  val writer = java.io.StringWriter()\n  forEach { writer.write(it) }\n  return writer.toString()\n}\n`,
      ),
    ).toBe("completed");
  });
  it("a servlet extension with no writes stays completed", async () => {
    expect(
      await status(
        `import javax.servlet.http.HttpServletResponse\nfun HttpServletResponse.ok() {\n  status = 200\n}\n`,
      ),
    ).toBe("completed");
  });
  it("an implicit writer in another type's extension makes it partial", async () => {
    expect(await status(`class Page\nfun Page.render() {\n  writer.write("x")\n}\n`)).toBe(
      "partial",
    );
  });
});

describe("ResponseEntity with an HTML content type is reported once (M18)", () => {
  const entity = (body: string): string =>
    `import org.springframework.web.bind.annotation.*;\nimport org.springframework.http.*;\n@RestController\nclass A {\n@GetMapping("/x") ResponseEntity<String> h(@RequestParam String name) {\n${body}\n}\n}\n`;
  const once = async (source: string) => (await xss(source, "A.java")).length;

  it("contentType(TEXT_HTML).body", async () => {
    expect(
      await once(
        entity(
          'return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body("<p>" + name + "</p>");',
        ),
      ),
    ).toBe(1);
  });
  it("status(...).contentType(...).body", async () => {
    expect(
      await once(
        entity(
          'return ResponseEntity.status(200).contentType(MediaType.TEXT_HTML).body("<p>" + name + "</p>");',
        ),
      ),
    ).toBe(1);
  });
  it("header(Content-Type, text/html).body", async () => {
    expect(
      await once(
        entity(
          'return ResponseEntity.ok().header("Content-Type", "text/html").body("<p>" + name + "</p>");',
        ),
      ),
    ).toBe(1);
  });
  it("the one finding says the content type is text/html", async () => {
    const found = await xss(
      entity(
        'return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body("<p>" + name + "</p>");',
      ),
      "A.java",
    );
    expect(found[0]?.evidence).toContain("content type text/html");
    expect(found[0]?.confidence).toBe("high");
  });
  it("a JSON content type on the entity is not reported at all", async () => {
    expect(
      await once(
        entity(
          'return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body("<p>" + name + "</p>");',
        ),
      ),
    ).toBe(0);
  });
  it("an entity with no content type is reported once, as a negotiated body", async () => {
    const found = await xss(
      entity('return ResponseEntity.ok().body("<p>" + name + "</p>");'),
      "A.java",
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.evidence).toContain("content type negotiated");
  });
  it("Kotlin expression body", async () => {
    const source = `import org.springframework.web.bind.annotation.*\nimport org.springframework.http.*\n@RestController\nclass A {\n  @GetMapping("/x") fun h(@RequestParam name: String) =\n    ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body("<p>$name</p>")\n}\n`;
    expect((await xss(source, "A.kt")).length).toBe(1);
  });
});
