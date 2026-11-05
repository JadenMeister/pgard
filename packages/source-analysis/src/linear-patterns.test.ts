import { describe, expect, it } from "vitest";
import { withoutTypeArguments } from "./jvm/kotlin-ir.js";
import { analyzeJsp, analyzeThymeleaf, looksLikeThymeleaf } from "./jvm/templates.js";
import { withoutTrailingQuotes } from "./python/analyze-python.js";

/**
 * The patterns the #368 audit found superlinear on the tree-sitter path (#371). A crafted input of
 * this size took tens of seconds with a quadratic pattern; with a linear one it takes milliseconds.
 * The limit is generous so a slow machine does not fail it, yet far below a quadratic run.
 */
const SIZE = 400_000;
const LIMIT_MS = 1_500;

function timed<T>(run: () => T): { value: T; ms: number } {
  const startedAt = performance.now();
  const value = run();
  return { value, ms: performance.now() - startedAt };
}

describe("withoutTrailingQuotes (Python string prefix)", () => {
  it.each([
    ['rb"""', "rb"],
    ["f'", "f"],
    ["r", "r"],
    ['"', ""],
    ["", ""],
    ['a"b"', 'a"b'],
    ["a'\"'x", "a'\"'x"],
  ])("matches replace(/[\"']+$/) on %j", (input, expected) => {
    expect(withoutTrailingQuotes(input)).toBe(expected);
    expect(input.replace(/["']+$/, "")).toBe(expected);
  });

  it("is linear on a long run of quotes followed by another character", () => {
    const input = `${'"'.repeat(SIZE)}x`;
    const { value, ms } = timed(() => withoutTrailingQuotes(input));
    expect(value).toBe(input);
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});

describe("withoutTypeArguments (Kotlin supertype name)", () => {
  it.each([
    ["List<String>", "List"],
    ["Map<String, List<Int>>", "Map"],
    ["Plain", "Plain"],
    ["A<B", "A<B"],
    ["A>B<", "A>B<"],
    ["A<B>C", "AC"],
    ["A<B>C<D>", "A"],
    ["A<\nB>", "A"],
  ])("matches replace(/<.*>/s) on %j", (input, expected) => {
    expect(withoutTypeArguments(input)).toBe(expected);
    expect(input.replace(/<.*>/s, "")).toBe(expected);
  });

  it("is linear on a long name with many '<' and no '>'", () => {
    const input = "<".repeat(SIZE);
    const { value, ms } = timed(() => withoutTypeArguments(input));
    expect(value).toBe(input);
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});

describe("template escaping helpers", () => {
  const page = (expression: string) => `<p th:utext="\${${expression}}">x</p>`;

  it("reads the helper name of an escaped Thymeleaf expression", () => {
    const analysis = analyzeThymeleaf(
      page("#strings.escapeXml(name)"),
      "templates/a.html",
      new Map(),
    );
    expect(analysis.kind).toBe("thymeleaf");
    expect(analysis.findings.map((finding) => finding.evidence)).toEqual([
      expect.stringContaining("escaped with #strings.escapeXml();"),
    ]);
  });

  it("finishes quickly on a long dotted name next to an escaping helper", () => {
    const expression = `${"a.".repeat(SIZE / 2)} #strings.escapeXml(${"a.".repeat(SIZE / 2)}`;
    const { ms } = timed(() => analyzeThymeleaf(page(expression), "templates/a.html", new Map()));
    expect(ms).toBeLessThan(LIMIT_MS * 4);
  });

  it("finishes quickly on a long whitespace run before the parenthesis of a JSP helper", () => {
    const text = `<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>\n<p>\${fn:escapeXml${" ".repeat(SIZE)}(param.a)}</p>`;
    const { ms } = timed(() => analyzeJsp(text, "web/a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS * 4);
  });
});

describe("escaping-helper patterns (#371 review)", () => {
  const jsp = (expression: string) => `<%@ page language="java" %>\n<p><%= ${expression} %></p>\n`;
  const thymeleaf = (expression: string) => `<p th:utext="\${${expression}}">x</p>`;

  it("keeps the helper judgement on small inputs", () => {
    const escaped = analyzeJsp(
      jsp('StringEscapeUtils.escapeHtml4(request.getParameter("a"))'),
      "a.jsp",
    );
    expect(escaped.findings.map((finding) => finding.evidence).join("\n")).toContain(
      "escaped with",
    );
    const thy = analyzeThymeleaf(
      thymeleaf("#strings.escapeXml(q) + htmlEscape(q)"),
      "templates/a.html",
      new Map(),
    );
    expect(thy.findings.map((finding) => finding.evidence).join("\n")).toContain("escaped with");
  });

  it("is linear on a repeated helper-name prefix in a Java expression", () => {
    const text = jsp(`${"escape".repeat(SIZE / 12)}.encodeForHTML(x)`);
    const { ms } = timed(() => analyzeJsp(text, "a.jsp"));
    expect(ms).toBeLessThan(LIMIT_MS);
  });

  it("is linear on a repeated htmlEscape prefix in a Thymeleaf expression", () => {
    const text = `<div th:utext="\${q} + \${'${"htmlEscape".repeat(SIZE / 10)}'}">x</div>`;
    const { ms } = timed(() => analyzeThymeleaf(text, "templates/a.html", new Map()));
    expect(ms).toBeLessThan(LIMIT_MS);
  });

  it.each([
    ["th:".repeat(SIZE / 6)],
    [`xmlns:th${" ".repeat(SIZE)}x`],
    ["[( ".repeat(SIZE / 6)],
    [`th:${"a".repeat(SIZE)}`],
  ])("looksLikeThymeleaf is linear on a crafted input", (input) => {
    const { ms } = timed(() => looksLikeThymeleaf(input));
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});
