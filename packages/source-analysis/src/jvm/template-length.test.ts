import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { analyzeJsp, analyzeThymeleaf } from "./templates.js";

/**
 * #508: a long expression is judged like a short one. Padding an expression past a length cap used
 * to drop its finding with no note. The lengths are the old caps (4000 for JSP EL, 500 for the
 * Thymeleaf inline form) with one length below and one above each.
 */
const JSP_LENGTHS = [10, 3990, 3999, 4000, 4001, 5000, 100_000];
const THYMELEAF_LENGTHS = [10, 400, 499, 500, 501, 600, 100_000];
const LIMIT_MS = 1_500;

function timed<T>(run: () => T): { value: T; ms: number } {
  const startedAt = performance.now();
  const value = run();
  return { value, ms: performance.now() - startedAt };
}

describe("a padded JSP expression is still judged (#508)", () => {
  it.each(JSP_LENGTHS)("EL in template text, %i spaces of padding", (padding) => {
    const analysis = analyzeJsp(`<p>\${param.q${" ".repeat(padding)}}</p>`, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high", status: "confirmed" });
    expect(analysis.notJudged ?? 0).toBe(0);
  });

  it.each(JSP_LENGTHS)("EL in an attribute, %i spaces of padding", (padding) => {
    const analysis = analyzeJsp(`<input value="\${param.q${" ".repeat(padding)}}">`, "a.jsp");
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high", status: "confirmed" });
    expect(analysis.notJudged ?? 0).toBe(0);
  });

  it.each(JSP_LENGTHS)('<c:out escapeXml="false">, %i spaces of padding', (padding) => {
    const analysis = analyzeJsp(
      `<c:out value="\${param.q${" ".repeat(padding)}}" escapeXml="false"/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ ruleId: "PG-XSS-004", severity: "high" });
    expect(analysis.notJudged ?? 0).toBe(0);
  });

  it("does not take a padded fn:escapeXml expression for a finding", () => {
    const analysis = analyzeJsp(`<p>\${fn:escapeXml(param.q)${" ".repeat(5000)}}</p>`, "a.jsp");
    expect(analysis.findings).toHaveLength(0);
  });

  it("does not make a c:set variable safe when its value is padded", () => {
    const analysis = analyzeJsp(
      `<c:set var="v" value="\${param.q${" ".repeat(5000)}}"/>\n<p>\${v}</p>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high" });
  });
});

describe("a padded Thymeleaf inline expression is still judged (#508)", () => {
  it.each(THYMELEAF_LENGTHS)("[( )] with %i spaces of padding", (padding) => {
    const analysis = analyzeThymeleaf(
      `<p>[(\${param.q}${" ".repeat(padding)})]</p>`,
      "templates/a.html",
      new Map(),
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high", status: "confirmed" });
  });

  it("finds every inline expression, one after the other", () => {
    const analysis = analyzeThymeleaf(
      "<p>[(${param.a})] and [(${param.b})]</p>\n<p>[(${param.c})]</p>",
      "templates/a.html",
      new Map(),
    );
    expect(analysis.findings.map((finding) => finding.line)).toEqual([1, 1, 2]);
  });
});

describe("hostile files with many openers stay fast and are not silent (#508)", () => {
  const MIB = 1024 * 1024;

  it("finishes on a megabyte of ${ that never close", () => {
    const text = `<p>${"${".repeat(MIB / 2)}`;
    const { value, ms } = timed(() => analyzeJsp(text, "a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(value.findings).toHaveLength(0);
  });

  it("finishes on a megabyte of ${' with an open quote", () => {
    const { ms } = timed(() => analyzeJsp(`<p>${"${'".repeat(MIB / 3)}`, "a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS);
  });

  it("finishes on a megabyte of openers with one closer, and says what was not judged", () => {
    const text = `<p>${"${".repeat(MIB / 2)}}`;
    const { value, ms } = timed(() => analyzeJsp(text, "a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(value.notJudged ?? 0).toBeGreaterThan(0);
  });

  it("finishes on a megabyte of [( that never close", () => {
    const text = `<p>${"[(".repeat(MIB / 2)}`;
    const { value, ms } = timed(() => analyzeThymeleaf(text, "templates/a.html", new Map()));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(value.findings).toHaveLength(0);
  });

  it("finishes on many [( openers with a closer at the end, and still finds the inline value", () => {
    const text = `<p>${"[(".repeat(MIB / 4)}\${param.q})]</p>`;
    const { value, ms } = timed(() => analyzeThymeleaf(text, "templates/a.html", new Map()));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(value.findings).toHaveLength(1);
  });

  it("finishes on a megabyte of unclosed tags", () => {
    const { ms } = timed(() => analyzeJsp(`\${x}${"<a ".repeat(MIB / 3)}`, "a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});

describe("long unquoted values, attribute names and tags (#508 review)", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });
  const LENGTHS = [1999, 2000, 2001, 100_000];

  it.each(LENGTHS)("an unquoted attribute value of %i characters before the EL", (length) => {
    const analysis = analyzeJsp(
      `<input type="text" value=${"x".repeat(length)}\${param.q}>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high" });
  });

  it.each(LENGTHS)("an unquoted c:out value of %i characters before the EL", (length) => {
    const analysis = analyzeJsp(
      `<c:out value=${"x".repeat(length)}\${param.q} escapeXml=false />`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high" });
  });

  it.each([199, 200, 201, 5000])(
    "an attribute name of %i characters does not hide the next attribute",
    (length) => {
      const analysis = analyzeJsp(`<input ${"n".repeat(length)}=1 value="\${param.q}">`, "a.jsp");
      expect(analysis.findings).toHaveLength(1);
      const cOut = analyzeJsp(
        `<c:out ${"n".repeat(length)}=1 value="\${param.q}" escapeXml="false"/>`,
        "a.jsp",
      );
      expect(cOut.findings).toHaveLength(1);
    },
  );

  it("reads a 200-character run glued to escapeXml as one attribute name", () => {
    // Intended: the attribute is named "nnn...escapeXml", not escapeXml, so escaping is not off.
    // The old 200-character name limit split it and exposed a false escapeXml="false".
    const analysis = analyzeJsp(
      `<c:out value="\${param.q}" ${"n".repeat(200)}escapeXml="false"/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(0);
  });

  it("still reports c:out when 20000 spaces come between the value and escapeXml", () => {
    const analysis = analyzeJsp(
      `<c:out value="\${param.q}"${" ".repeat(20_000)} escapeXml="false"/>`,
      "a.jsp",
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({ severity: "high" });
    expect(analysis.findings[0]?.cause).toContain("jsp-c-out");
  });

  it("scans a long unquoted value through the whole scan", async () => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-tpl-bare-")));
    roots.push(root);
    mkdirSync(path.join(root, "web"), { recursive: true });
    writeFileSync(path.join(root, "pom.xml"), "<project/>\n");
    writeFileSync(
      path.join(root, "web", "a.jsp"),
      `<input type="text" value=${"x".repeat(2000)}\${param.q}>\n`,
    );
    const output = await scanSourceCode(root);
    expect(output.findings.filter((item) => item.ruleId === "PG-XSS-004")).toHaveLength(1);
  });
});

describe("unclosed openers do not starve the budget (#508 review)", () => {
  it("still reports the finding after a few unclosed ${ in a 400 KB file", () => {
    const text = `<!-- \${\${\${\${\${\${\${\${\${\${ -->${"<p>hello</p>\n".repeat(30_000)}<p>\${param.q}</p><script>}</script>`;
    const analysis = analyzeJsp(text, "a.jsp");
    // The last opener of the comment now reaches the stray `}` in the script and is judged too.
    const lastLine = 30_001;
    expect(analysis.findings.some((f) => f.line === lastLine && f.severity === "high")).toBe(true);
    expect(analysis.notJudged ?? 0).toBe(0);
  });
});

describe("a Thymeleaf inline stops at the tag (#508 review)", () => {
  it("does not read an array index in a script as an inline expression", () => {
    const text = `<script>var a = arr[(i + 1) % n];</script>\n<span th:text="\${param.q}">x</span>\n${"<p>row</p>\n".repeat(60)}<script>var b = list[indexOf(x)];</script>`;
    expect(analyzeThymeleaf(text, "templates/a.html", new Map()).findings).toHaveLength(0);
  });

  it("does not let an inline body cross a tag outside a script", () => {
    const text = `<p>[(\${param.q}</p><p>)]</p>`;
    expect(analyzeThymeleaf(text, "templates/a.html", new Map()).findings).toHaveLength(0);
  });

  it("still reads an inline in a script and a padded one in text", () => {
    const script = analyzeThymeleaf(
      `<script>var x = [(\${param.q}<b)];</script>`,
      "templates/a.html",
      new Map(),
    );
    expect(script.findings).toHaveLength(1);
    const padded = analyzeThymeleaf(
      `<p>[(\${param.q}${" ".repeat(100_000)})]</p>`,
      "templates/a.html",
      new Map(),
    );
    expect(padded.findings).toHaveLength(1);
  });

  it("stays linear with many openers that cross a tag", () => {
    const text = `<p>${"[(".repeat(200_000)}<b>x</b>)]</p>`;
    const { ms } = timed(() => analyzeThymeleaf(text, "templates/a.html", new Map()));
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});

describe("the scan says when a template was not fully judged (#508)", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });

  it("reports a partial template area, not a clean one", async () => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-tpl-len-")));
    roots.push(root);
    mkdirSync(path.join(root, "web"), { recursive: true });
    writeFileSync(path.join(root, "pom.xml"), "<project/>\n");
    writeFileSync(path.join(root, "web", "a.jsp"), `<p>${"${".repeat(200_000)}}</p>\n`);
    const output = await scanSourceCode(root);
    const entry = output.coverage.find((item) => item.area === "source:jvm-templates");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("were not judged");
  });
});
