import { mkdirSync, mkdtempSync, realpathSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { MAX_FILE_BYTES } from "../walk.js";
import { analyzeJsp } from "./templates.js";

/** #510 and #511: input that is too large or not understood is judged or reported, never safe. */

const LIMIT_MS = 1_500;
const THYMELEAF_HEAD = '<html xmlns:th="http://www.thymeleaf.org"><p th:utext="${param.q}"></p>';

function timed<T>(run: () => T): { value: T; ms: number } {
  const startedAt = performance.now();
  const value = run();
  return { value, ms: performance.now() - startedAt };
}

/** An HTML file of exactly `size` bytes: `head`, a comment of padding, `</html>`. */
function htmlOfSize(head: string, size: number): string {
  const tail = "-->\n</html>";
  const open = `${head}<!--`;
  return `${open}${"x".repeat(size - open.length - tail.length)}${tail}`;
}

describe("a big .html file is not skipped silently (#510)", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });

  function project(): string {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-big-html-")));
    roots.push(root);
    mkdirSync(path.join(root, "templates"), { recursive: true });
    writeFileSync(path.join(root, "pom.xml"), "<project/>\n");
    return root;
  }

  async function scanHtml(source: string | Buffer) {
    const root = project();
    writeFileSync(path.join(root, "templates", "a.html"), source);
    const output = await scanSourceCode(root);
    return {
      entry: output.coverage.find((item) => item.area === "source:jvm-templates"),
      found: output.findings.filter((finding) => finding.location.path?.endsWith("a.html")),
    };
  }

  it.each([MAX_FILE_BYTES - 1, MAX_FILE_BYTES])(
    "judges a template of %i bytes and reports nothing as skipped",
    async (size) => {
      const { entry, found } = await scanHtml(htmlOfSize(THYMELEAF_HEAD, size));
      expect(found).toHaveLength(1);
      expect(entry?.status).toBe("completed");
      expect(entry?.note).not.toContain("over 1 MiB");
    },
  );

  it.each([MAX_FILE_BYTES + 1, 3 * MAX_FILE_BYTES])(
    "reports a Thymeleaf template of %i bytes as not analyzed, with a count only",
    async (size) => {
      const { entry, found } = await scanHtml(htmlOfSize(THYMELEAF_HEAD, size));
      expect(found).toHaveLength(0);
      expect(entry?.status).toBe("partial");
      expect(entry?.note).toContain("1 HTML file(s) over 1 MiB");
      expect(entry?.note).not.toContain("a.html");
    },
  );

  it("finds a Thymeleaf marker that comes after more than one chunk of padding", async () => {
    const padding = "x".repeat(2 * MAX_FILE_BYTES + 5);
    const { entry } = await scanHtml(
      `<html><!--${padding}--><p th:utext="\${param.q}"></p></html>`,
    );
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("1 HTML file(s) over 1 MiB");
  });

  it("finds a marker that straddles a chunk boundary", async () => {
    // `xmlns:th` starts a few bytes before the 1 MiB boundary and ends after it.
    const before = "<html><!--";
    const text = `${before}${"x".repeat(MAX_FILE_BYTES - before.length - 8)}--> xmlns:th="x"></html>${"y".repeat(MAX_FILE_BYTES)}`;
    const at = text.indexOf("xmlns:th");
    expect(at).toBeLessThan(MAX_FILE_BYTES);
    expect(at + 8).toBeGreaterThan(MAX_FILE_BYTES);
    const { entry } = await scanHtml(text);
    expect(entry?.note).toContain("1 HTML file(s) over 1 MiB");
  });

  it("does not count a big plain HTML page", async () => {
    const { entry } = await scanHtml(`<html><body>${"<p>row</p>\n".repeat(200_000)}</body></html>`);
    expect(entry?.note ?? "").not.toContain("over 1 MiB");
    expect(entry?.status ?? "completed").toBe("completed");
  });

  it("does not count a big binary file with an .html name", async () => {
    const { entry } = await scanHtml(Buffer.alloc(MAX_FILE_BYTES + 10, 0));
    expect(entry?.note ?? "").not.toContain("over 1 MiB");
  });

  it("counts a file too large to test as not analyzed, not as clean", async () => {
    const root = project();
    const file = path.join(root, "templates", "huge.html");
    writeFileSync(file, "");
    truncateSync(file, 40 * 1024 * 1024); // sparse: no real disk use
    const output = await scanSourceCode(root);
    const entry = output.coverage.find((item) => item.area === "source:jvm-templates");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("1 HTML file(s) over 1 MiB");
  });
});

describe("c:out and c:set judge every expression of a value (#511 item 1)", () => {
  it("finds a tainted second expression in c:out", () => {
    const analysis = analyzeJsp(`<c:out value="\${'a'}\${param.q}" escapeXml="false"/>`, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ ruleId: "PG-XSS-004", severity: "high" });
  });

  it("finds a tainted third expression after escaped and constant ones", () => {
    const analysis = analyzeJsp(
      `<c:out value="\${fn:escapeXml(param.a)}\${'x'}\${header.h}" escapeXml="false"/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
  });

  it("does not report constant and escaped expressions", () => {
    const analysis = analyzeJsp(
      `<c:out value="\${'a'}\${fn:escapeXml(param.q)}\${1}" escapeXml="false"/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(0);
  });

  it("does not report a tainted c:out that keeps escapeXml on", () => {
    const analysis = analyzeJsp(`<c:out value="\${'a'}\${param.q}"/>`, "a.jsp");
    expect(analysis.findings).toHaveLength(0);
  });

  it("marks a c:set variable tainted by its second expression", () => {
    const analysis = analyzeJsp(
      `<c:set var="v" value="\${'a'}\${param.q}"/>\n<c:out value="\${v}" escapeXml="false"/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
  });

  it("keeps a c:set variable of constants and escaped values safe", () => {
    const analysis = analyzeJsp(
      `<c:set var="v" value="\${'a'}\${fn:escapeXml(param.q)}"/>\n<c:out value="\${v}" escapeXml="false"/>`,
      "a.jsp",
    );
    // `${v}` is a variable of no known source: at most a low, inferred note, never a high finding.
    expect(analysis.findings.filter((finding) => finding.severity === "high")).toHaveLength(0);
  });

  it("is linear with many expressions in one value", () => {
    const text = `<c:out value="${"${'a'}".repeat(150_000)}\${param.q}" escapeXml="false"/>`;
    const { value, ms } = timed(() => analyzeJsp(text, "a.jsp"));
    expect(value.findings).toHaveLength(1);
    expect(ms).toBeLessThan(LIMIT_MS);
  });

  it("stays bounded with many unclosed openers in one value, and counts what it skipped", () => {
    const text = `<c:out value="${"${".repeat(200_000)}" escapeXml="false"/>}`;
    const { value, ms } = timed(() => analyzeJsp(text, "a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS * 2);
    // Either judged or counted, never silently dropped.
    expect(value.findings.length + (value.notJudged ?? 0)).toBeGreaterThan(0);
  });
});

describe("EL outside an attribute value is scanned (#511 item 2)", () => {
  it.each([
    ["a bare expression in a tag", "<div ${param.q}>x</div>"],
    ["between attributes", '<div class="a" ${param.q} id="b">x</div>'],
    ["with spaces in it", "<div ${param.q + 'x'}>x</div>"],
    ["as part of an attribute name", "<div data-${param.q}=1>x</div>"],
    ["right after the tag name", "<div${param.q}>x</div>"],
    ["with a > inside the expression", "<div ${param.q > 1}>x</div>"],
  ])("finds %s", (_label, source) => {
    const analysis = analyzeJsp(source, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ ruleId: "PG-XSS-004", severity: "high" });
  });

  it("does not report a constant, an escaped or a model-free expression in a tag", () => {
    for (const source of [
      "<div ${'a'}>x</div>",
      "<div ${fn:escapeXml(param.q)}>x</div>",
      '<div class="a" id="b">x</div>',
    ]) {
      expect(analyzeJsp(source, "a.jsp").findings).toHaveLength(0);
    }
  });

  it("does not make a high finding of an expression of no known source", () => {
    const analysis = analyzeJsp("<div ${pageScope.title}>x</div>", "a.jsp");
    expect(analysis.findings.filter((finding) => finding.severity === "high")).toHaveLength(0);
  });

  it("does not count the same expression twice", () => {
    expect(analyzeJsp('<div class="${param.q}" ${param.r}>x</div>', "a.jsp").findings).toHaveLength(
      2,
    );
    expect(analyzeJsp('<div class="${param.q}">x</div>', "a.jsp").findings).toHaveLength(1);
  });

  it("stays linear with a huge tag of expressions between attributes", () => {
    const text = `<div ${"${a} ".repeat(150_000)}${"${param.q} "}>x</div>`;
    const { value, ms } = timed(() => analyzeJsp(text, "a.jsp"));
    expect(value.findings.length).toBeGreaterThanOrEqual(1);
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});

describe("a single-quoted value that holds quotes inside its expression (#511 item 3)", () => {
  // Jasper (Tomcat) finds the end of an attribute value with EL awareness only when
  // quoteAttributeEL is false; by default (true) the first matching quote ends the value, so
  // `value='${param['q']}'` does not compile there. Other containers and configurations accept
  // it, and a page that does not compile has no runtime finding anyway, so the expression is
  // judged as written: a finding where the value is tainted, none where it is escaped or constant.
  it("finds a tainted expression with nested quotes", () => {
    const analysis = analyzeJsp(`<c:out value='\${param['q']}' escapeXml='false'/>`, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high" });
  });

  it("finds it in a double-quoted value with double quotes inside", () => {
    const analysis = analyzeJsp(`<c:out value="\${param["q"]}" escapeXml="false"/>`, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
  });

  it("does not report an escaped or constant expression with nested quotes", () => {
    for (const value of [`\${fn:escapeXml(param['q'])}`, `\${'a'}\${'b'}`]) {
      const analysis = analyzeJsp(`<c:out value='${value}' escapeXml='false'/>`, "a.jsp");
      expect(analysis.findings).toHaveLength(0);
    }
  });

  it("marks a c:set variable tainted with nested quotes", () => {
    const analysis = analyzeJsp(
      `<c:set var='v' value='\${param['q']}'/>\n<c:out value='\${v}' escapeXml='false'/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
  });
});

describe("a long attribute name hides nothing (#511 item 4)", () => {
  // The 200-character cut of attribute names was removed with the other caps (#508); this pins
  // that a name of any length neither hides the expression in its value nor the attribute after it.
  it.each([199, 200, 201, 5_000, 200_000])(
    "finds EL in the value of an attribute whose name is %i characters",
    (length) => {
      const analysis = analyzeJsp(`<div ${"a".repeat(length)}="\${param.q}">x</div>`, "a.jsp");
      expect(analysis.findings).toHaveLength(1);
    },
  );

  it.each([201, 5_000])(
    "still reads escapeXml and value after a %i-character attribute name",
    (length) => {
      const analysis = analyzeJsp(
        `<c:out ${"a".repeat(length)}="1" value="\${param.q}" escapeXml="false"/>`,
        "a.jsp",
      );
      expect(analysis.findings).toHaveLength(1);
    },
  );

  it("does not report a long-named attribute with a constant value", () => {
    expect(analyzeJsp(`<div ${"a".repeat(5_000)}="x">x</div>`, "a.jsp").findings).toHaveLength(0);
  });

  it("finds a value after a 5000-character unquoted value", () => {
    const analysis = analyzeJsp(`<div a=${"x".repeat(5_000)} b="\${param.q}">x</div>`, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
  });
});
