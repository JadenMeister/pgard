import { describe, expect, it } from "vitest";
import {
  CRYPTO_PASSWORD_CONTEXT,
  GENERIC_KEY_PROPERTY,
  KEY_PROPERTY,
  NOT_A_CRYPTO_KEY_CONTEXT,
  PASSWORD_PROPERTY,
} from "./jvm/crypto-rules.js";
import { analyzeGoSource } from "./go/analyze-go.js";
import { analyzeJsSource } from "./js/analyze-js.js";
import { analyzeJvmTree, assignCountsOf } from "./jvm/analyze-jvm.js";
import { elementTypeOf } from "./jvm/flow-values.js";
import { analyzeVueSource } from "./vue/analyze-vue.js";
import { withoutTypeArguments } from "./jvm/kotlin-ir.js";
import { TreeSitterRuntime } from "./tree-sitter/runtime.js";
import {
  analyzeJsp,
  analyzeThymeleaf,
  elJudge,
  looksLikeThymeleaf,
  THYMELEAF_ESCAPE,
} from "./jvm/templates.js";
import { withoutTrailingQuotes } from "./python/analyze-python.js";
import { matchesTemplate, modelAttributeName, normalizePath } from "./jvm/view-links.js";

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

describe("elementTypeOf (loop variable type from a typed collection, #295)", () => {
  it.each([
    ["List<LogEntry>", "LogEntry"],
    ["MutableList<LogEntry?>", "LogEntry"],
    ["Array<LogEntry>", "LogEntry"],
    ["LogEntry[]", "LogEntry"],
    ["List<? extends LogEntry>", "LogEntry"],
    ["List<out LogEntry>", "LogEntry"],
    ["Set<a.b.LogEntry>", "a.b.LogEntry"],
    ["Map<String, LogEntry>", null],
    ["List<*>", null],
    ["List<T>", "T"],
    ["Plain", null],
    ["", null],
  ])("reads %j", (input, expected) => {
    expect(elementTypeOf(input)).toBe(expected);
  });

  it("is linear on a long type with many '<' and no '>'", () => {
    for (const input of [
      `List${"<".repeat(SIZE)}`,
      `List<${"A<".repeat(SIZE)}>`,
      "A[]".repeat(SIZE),
    ]) {
      const { ms } = timed(() => elementTypeOf(input));
      expect(ms).toBeLessThan(LIMIT_MS);
    }
  });
});

describe("conditions kept in variables, field and receiver checks (#294, #295, #286)", () => {
  it("stays linear in a file with a thousand condition variables and tests", async () => {
    const runtime = new TreeSitterRuntime();
    try {
      const lines: string[] = [];
      for (let i = 0; i < 1500; i += 1) {
        lines.push(
          `boolean ok${i} = x.normalize().startsWith(base) && ${"a".repeat(200)}.contains(x);`,
          `if (!ok${i}) throw new SecurityException();`,
        );
      }
      const source = `import java.nio.file.*;\nclass A { void h(Path x, Path base) throws Exception {\n${lines.join("\n")}\nFiles.readAllBytes(x);\n} }\n`;
      const outcome = await runtime.parse("java", source);
      if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
      const { ms } = timed(() => analyzeJvmTree(outcome.tree.rootNode, source, "A.java", "java"));
      outcome.dispose();
      expect(ms).toBeLessThan(LIMIT_MS * 4);
    } finally {
      runtime.dispose();
    }
  });
});

describe("assignCountsOf (#286 review)", () => {
  it("counts names followed by an assignment operator, not comparisons", () => {
    const counts = assignCountsOf(
      "a = 1; b += 2; c == 3; d <= 4; e != 5; this.f = 6; g -> 7; h >>= 1",
    );
    expect([...counts.entries()]).toEqual([
      ["a", 1],
      ["b", 1],
      ["f", 1],
      ["h", 1],
    ]);
  });

  it("is linear on long identifiers, digits and whitespace runs", () => {
    for (const input of [
      "a".repeat(SIZE),
      `${"a".repeat(SIZE)}=`,
      "1".repeat(SIZE) + "a",
      `a${" ".repeat(SIZE)}b`,
      "a ".repeat(SIZE / 2),
      "a=".repeat(SIZE / 2),
    ]) {
      const { ms } = timed(() => assignCountsOf(input));
      expect(ms).toBeLessThan(LIMIT_MS);
    }
  });
});

describe("condition expansion has a budget for the whole file (re-review)", () => {
  it("does not pay for thousands of tests that name conditions, and keeps the finding", async () => {
    const runtime = new TreeSitterRuntime();
    try {
      const decl = Array.from(
        { length: 7 },
        (_, i) => `boolean a${i} = q.startsWith("x") && q.contains("y");`,
      ).join("\n");
      const names = Array.from({ length: 7 }, (_, i) => `a${i}`).join("&&");
      const tests = Array.from(
        { length: 6000 },
        () => `if (!(${names})) throw new IllegalStateException();`,
      ).join("\n");
      const source = `import org.springframework.web.bind.annotation.*;\nimport org.springframework.jdbc.core.JdbcTemplate;\nclass A { JdbcTemplate jdbc;\n@GetMapping("/x") void h(@RequestParam String q) {\n${decl}\n${tests}\njdbc.queryForList("select " + q);\n}\n}\n`;
      const outcome = await runtime.parse("java", source);
      if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
      const { value, ms } = timed(() =>
        analyzeJvmTree(outcome.tree.rootNode, source, "A.java", "java"),
      );
      outcome.dispose();
      expect(ms).toBeLessThan(LIMIT_MS);
      expect(value.findings.some((f) => f.ruleId === "PG-SQL-005")).toBe(true);
    } finally {
      runtime.dispose();
    }
  });
});

describe("condition expansion is capped (#295 review)", () => {
  it("does not grow a test that names many long conditions, and keeps the finding", async () => {
    const runtime = new TreeSitterRuntime();
    try {
      const long = `q.startsWith("${"x".repeat(230)}") && q.contains("y")`;
      const decl = Array.from({ length: 150 }, (_, i) => `boolean a${i} = ${long};`).join("\n");
      const names = Array.from({ length: 150 }, (_, i) => `a${i}`)
        .join("&&")
        .slice(0, 590)
        .replace(/&&?a?\d*$/, "");
      const tests = Array.from(
        { length: 300 },
        () => `if (!(${names})) throw new IllegalStateException();`,
      ).join("\n");
      const source = `import org.springframework.web.bind.annotation.*;\nimport org.springframework.jdbc.core.JdbcTemplate;\nclass A { JdbcTemplate jdbc;\n@GetMapping("/x") void h(@RequestParam String q) {\n${decl}\n${tests}\njdbc.queryForList("select " + q);\n}\n}\n`;
      const outcome = await runtime.parse("java", source);
      if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
      const { value, ms } = timed(() =>
        analyzeJvmTree(outcome.tree.rootNode, source, "A.java", "java"),
      );
      outcome.dispose();
      expect(ms).toBeLessThan(LIMIT_MS * 2);
      // Past the cap nothing is expanded, so the finding is not silenced.
      expect(value.findings.some((f) => f.ruleId === "PG-SQL-005" && f.confidence === "high")).toBe(
        true,
      );
    } finally {
      runtime.dispose();
    }
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

describe("Thymeleaf sanitize helper pattern (#494)", () => {
  const page = (expression: string) => `<p th:utext="\${${expression}}">x</p>`;
  const evidence = (expression: string) =>
    analyzeThymeleaf(page(expression), "templates/a.html", new Map())
      .findings.map((finding) => finding.evidence)
      .join("\n");

  it.each([
    ["#strings.sanitize(x)", "escaped with #strings.sanitize();"],
    ["#sanitizer.sanitize (x)", "escaped with #sanitizer.sanitize();"],
    ["#sanitizeHtml(x)", "escaped with #sanitizeHtml();"],
    ["#xsanitize(x)", "escaped with #xsanitize();"],
  ])("still reads %s as an escaping helper", (expression, expected) => {
    expect(evidence(expression)).toContain(expected);
  });

  it("does not treat a name that only mentions sanitize as a helper", () => {
    expect(evidence("#strings.sanitize + q")).not.toContain("escaped with");
    expect(evidence("sanitize(x)")).not.toContain("escaped with");
  });

  it("matches the same text as the former branch on every short string", () => {
    // The shipped pattern against the same pattern with the former sanitize branch put back.
    const shippedBranch = String.raw`#(?:(?!sanitize)\w)*sanitize\w*\s*\(|#\w*\.sanitize\w*\s*\(`;
    expect(THYMELEAF_ESCAPE.source).toContain(shippedBranch);
    const former = new RegExp(
      THYMELEAF_ESCAPE.source.replace(shippedBranch, String.raw`#\w*\.?sanitize\w*\s*\(`),
    );
    const current = new RegExp(THYMELEAF_ESCAPE.source);
    const alphabet = ["#", ".", "sanitize", "SANITIZE", "san", "x", "_", "1", " ", "\n", "\t", "("];
    const seen: string[] = [];
    const walk = (text: string, depth: number): void => {
      seen.push(text);
      if (depth > 0) for (const part of alphabet) walk(text + part, depth - 1);
    };
    walk("", 4);
    let mismatches = 0;
    for (const text of seen) {
      const a = former.exec(text);
      const b = current.exec(text);
      if (a?.index !== b?.index || a?.[0] !== b?.[0]) mismatches += 1;
    }
    expect(seen.length).toBeGreaterThan(20_000);
    expect(mismatches).toBe(0);
  });

  it.each([
    ["a repeated sanitize word", `#${"sanitize".repeat(SIZE / 8)}`],
    ["a repeated sanitize word after a dot", `#a.${"sanitize".repeat(SIZE / 8)}`],
    ["a long space run before the parenthesis", `#sanitize${" ".repeat(SIZE)}`],
  ])("is linear on %s", (_name, expression) => {
    const { ms } = timed(() => analyzeThymeleaf(page(expression), "templates/a.html", new Map()));
    expect(ms).toBeLessThan(LIMIT_MS);
  });
});

describe("escape-call stripping is linear in the number of calls (#506)", () => {
  // MAX_FILE_BYTES is 1 MiB; this is a template of about that size. The former code copied the body
  // once per 20 calls and ran out of memory (or stack) here, which made the file `partial`.
  const MAX_BODY = 1_048_000;
  const page = (expression: string) => `<p th:utext="\${${expression}}">x</p>`;
  const found = (expression: string) =>
    analyzeThymeleaf(page(expression), "templates/a.html", new Map()).findings;

  it.each([["htmlEscape(x)+"], ["#sanitize(x)+"], ["#strings.escapeXml(x)+"], ["forHtml(x) + "]])(
    "reports param.q after about 1 MiB of %s",
    (unit) => {
      const expression = `${unit.repeat(Math.floor(MAX_BODY / unit.length))}param.q`;
      const { value, ms } = timed(() => found(expression));
      expect(ms).toBeLessThan(LIMIT_MS);
      expect(value).toHaveLength(1);
      expect(value[0]?.evidence).toContain("param / request");
    },
  );

  it("reports param.q after about 1 MiB of nested calls", () => {
    const depth = Math.floor(MAX_BODY / 12);
    const expression = `${"htmlEscape(".repeat(depth)}x${")".repeat(depth)}+param.q`;
    const { value, ms } = timed(() => found(expression));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(value).toHaveLength(1);
  });

  it("reports param.q after about 1 MiB of unclosed calls", () => {
    // The first call never closes, so it takes the rest of the body: the request input is inside it
    // and the expression is still judged, never skipped.
    const expression = `param.q+${"htmlEscape(x+".repeat(Math.floor(MAX_BODY / 13))}`;
    const { value, ms } = timed(() => found(expression));
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(value).toHaveLength(1);
  });

  it("still calls a fully escaped body escaped, and a body with request input outside tainted", () => {
    const call = "htmlEscape(x)+";
    const escaped = found(`${call.repeat(50_000)}'a'`);
    expect(escaped.map((finding) => finding.evidence).join("\n")).toContain(
      "escaped with htmlEscape()",
    );
    expect(found(`${call.repeat(50_000)}param.q`)[0]?.evidence).toContain("param / request");
  });

  it.each([["fn:escapeXml(x)+"], ["fn : escapeXml(x) + "]])(
    "judges about 1 MiB of %s by the request input left outside the calls",
    (unit) => {
      const body = unit.repeat(Math.floor(MAX_BODY / unit.length));
      const tainted = timed(() => elJudge(`${body}param.q`, new Map()));
      expect(tainted.ms).toBeLessThan(LIMIT_MS);
      expect(tainted.value.cls).toBe("tainted");
      const rest = timed(() => elJudge(`${body}'a'`, new Map()));
      expect(rest.ms).toBeLessThan(LIMIT_MS);
      expect(rest.value.cls).not.toBe("tainted");
    },
  );
});

describe("JVM configuration key patterns (#350)", () => {
  const inputs = {
    dots: "a.".repeat(SIZE / 2),
    dashes: "key-".repeat(SIZE / 4),
    nearMiss: `${"key-store.".repeat(SIZE / 10)}x`,
    spaced: `${"ssl-".repeat(SIZE / 4)}!`,
  };
  const patterns = [
    ["PASSWORD_PROPERTY", PASSWORD_PROPERTY],
    ["CRYPTO_PASSWORD_CONTEXT", CRYPTO_PASSWORD_CONTEXT],
    ["GENERIC_KEY_PROPERTY", GENERIC_KEY_PROPERTY],
    ["NOT_A_CRYPTO_KEY_CONTEXT", NOT_A_CRYPTO_KEY_CONTEXT],
    ["KEY_PROPERTY", KEY_PROPERTY],
  ] as const;
  for (const [name, pattern] of patterns) {
    it.each(Object.entries(inputs))(`${name} is linear on %s`, (_label, input) => {
      const { ms } = timed(() => pattern.test(input));
      expect(ms).toBeLessThan(LIMIT_MS);
    });
  }
});

describe("JavaScript route and protection detection (#302)", () => {
  it("stays bounded on many route registrations and a long middleware chain", () => {
    // The receiver chain is 500 segments deep: the analyzer recurses once per segment, and a deeper
    // chain overflows a small stack (see hostile-limits.test.ts for what a scan does then).
    const routes = Array.from({ length: 5_000 }, (_, i) => `x${i}.post('/p${i}', (a, b) => a);`);
    const chain = `app.post('/login', ${Array.from({ length: 5_000 }, () => "limiter").join(", ")}, h);`;
    const code = `import rateLimit from 'express-rate-limit';\nconst limiter = rateLimit();\n${routes.join("\n")}\n${"a.b.".repeat(250)}c.post('/x', () => 1);\n${chain}\n`;
    const { value, ms } = timed(() => analyzeJsSource(code, "a.js"));
    expect(ms).toBeLessThan(LIMIT_MS * 4);
    expect(value.facts.unrecognizedRoutes).toBe(5_001);
    expect(value.facts.authRoutes).toEqual([{ line: 5_004, routePath: "/login", limited: true }]);
  });

  it("stays linear on nested routes that use a limiter and a CSRF name", () => {
    const head =
      "import express from 'express';\nimport rateLimit from 'express-rate-limit';\nimport csrf from 'csurf';\nconst app = express();\nconst limiter = rateLimit();\nconst cp = csrf();\n";
    const chain = (depth: number) =>
      "app.post('/login', (q, r) => {".repeat(depth) + "limiter(); cp();" + "});".repeat(depth);
    const code = head + Array.from({ length: 100 }, () => chain(100)).join("\n");
    const small = head + Array.from({ length: 25 }, () => chain(100)).join("\n");
    analyzeJsSource(small, "a.js");
    const quarter = timed(() => analyzeJsSource(small, "a.js")).ms;
    const { value, ms } = timed(() => analyzeJsSource(code, "a.js"));
    expect(value.facts.authRoutes).toHaveLength(10_000);
    // Only the innermost handler of each chain uses the names; four times the input stays far
    // from the sixteen times a repeated subtree scan would cost.
    expect(ms).toBeLessThan(LIMIT_MS * 4);
    expect(ms / Math.max(quarter, 1)).toBeLessThan(12);
  });

  it("stays linear on references nested deep inside one handler", () => {
    const head =
      "import express from 'express';\nimport rateLimit from 'express-rate-limit';\nconst app = express();\nconst limiter = rateLimit();\n";
    // 300 levels of 300 identifiers (about 700 KiB). The control has the same shape with a name
    // that is not a limiter, so only the cost of the usage climb differs between the two.
    const build = (name: string) => {
      let inner = `${name},`.repeat(300);
      for (let i = 1; i < 300; i += 1) inner = `${`${name},`.repeat(300)}[${inner}]`;
      return `${head}app.post('/login', () => [${inner}]);\n`;
    };
    const withLimiter = build("limiter");
    const control = build("other");
    analyzeJsSource(control, "a.js");
    const baseline = Math.max(timed(() => analyzeJsSource(control, "a.js")).ms, 1);
    const { value, ms } = timed(() => analyzeJsSource(withLimiter, "a.js"));
    expect(value.facts.authRoutes).toEqual([{ line: 5, routePath: "/login", limited: true }]);
    expect(ms).toBeLessThan(LIMIT_MS * 4);
    // A walk up from every reference (no memo) costs about four times the control here.
    expect(ms / baseline).toBeLessThan(2.5);
  });
});

describe("sanitizer configuration and attribute-context patterns (#278)", () => {
  const head = "import DOMPurify from 'dompurify';\n";

  it("stays linear on a long run of attribute-like text before a sanitizer call", () => {
    const run = (n: number) =>
      `${head}el.innerHTML = '<a ${"b=".repeat(n)}' + DOMPurify.sanitize(location.hash);\n`;
    analyzeJsSource(run(10), "a.js");
    const { value, ms } = timed(() => analyzeJsSource(run(100_000), "a.js"));
    expect(ms).toBeLessThan(LIMIT_MS * 4);
    expect(value.findings.length).toBeGreaterThan(0);
  });

  it("stays linear on a long options list and a hook-heavy file", () => {
    const run = (n: number) => {
      const tags = Array.from({ length: n }, (_, i) => `'t${i}'`).join(",");
      const hooks = "DOMPurify.addHook('x', f);\n".repeat(n);
      const code = `${head}${hooks}el.innerHTML = DOMPurify.sanitize(location.hash, { ADD_TAGS: [${tags}] });\n`;
      return timed(() => analyzeJsSource(code, "a.js"));
    };
    run(100);
    const small = run(2_500);
    const large = run(10_000);
    expect(large.value.findings.length).toBe(1);
    // Four times the input: linear is about 4, quadratic about 16. The floor and the generous
    // absolute bound keep a slow (Windows) runner from failing it.
    expect(large.ms / Math.max(small.ms, 25)).toBeLessThan(12);
    expect(large.ms).toBeLessThan(LIMIT_MS * 8);
  });
});

describe("Vue template scopes stay linear (#278 review)", () => {
  it("does not copy every outer alias at each nesting level", () => {
    const aliases = Array.from({ length: 100 }, (_, i) => `a${i}`).join(", ");
    const nested = `<div v-for="(${aliases}) in list" :key="1">`.repeat(300);
    const leaves = '<i v-for="(x, y) in list" :key="y"></i>'.repeat(800);
    const code = `<template>${nested}${leaves}<b v-html="DOMPurify.sanitize(h)"></b><u v-html="$route.query.x"></u>${"</div>".repeat(300)}</template>\n<script setup>\nimport DOMPurify from "dompurify";\n</script>\n`;
    const { value, ms } = timed(() => analyzeVueSource(code, "a.vue"));
    expect(value.findings).toHaveLength(1);
    // Copying every outer alias at each level took about 14 s here; linear takes well under 1 s.
    expect(ms).toBeLessThan(LIMIT_MS * 8);
  });
});

describe("view and mapping patterns (#338)", () => {
  it("normalizePath is linear on long runs of slashes, dots and a long query", () => {
    for (const input of [
      "/".repeat(SIZE),
      `${"a/".repeat(SIZE / 2)}?${"&".repeat(SIZE)}`,
      `${".".repeat(SIZE)}/x`,
    ]) {
      const { value, ms } = timed(() => normalizePath(input));
      expect(typeof value).toBe("string");
      expect(ms).toBeLessThan(LIMIT_MS);
    }
    expect(normalizePath("//a///b/?x=1#f")).toBe("/a/b");
    expect(normalizePath("")).toBe("/");
  });
  it("matchesTemplate is linear on many segments and long braces", () => {
    const many = "/a".repeat(SIZE / 4);
    const braces = `/${"{".repeat(SIZE)}`;
    for (const [mapping, target] of [
      [many, many],
      [braces, `/${"x".repeat(SIZE)}`],
      [`${many}/{id}`, `${many}/${"9".repeat(SIZE / 2)}`],
    ] as const) {
      const { ms } = timed(() => matchesTemplate(mapping, target));
      expect(ms).toBeLessThan(LIMIT_MS);
    }
    expect(matchesTemplate("/items/{id}", "/items/7")).toBe(true);
    expect(matchesTemplate("/items/{id}", "/items/7/x")).toBe(false);
  });
  it("modelAttributeName is linear on long return types", () => {
    const annotation = { name: "ModelAttribute", value: null, named: new Map(), line: 1 };
    for (const type of [
      "a.".repeat(SIZE / 2),
      `List<${"a.".repeat(SIZE / 2)}`,
      "A".repeat(SIZE),
      `${"List<".repeat(SIZE / 8)}x`,
    ]) {
      const { ms } = timed(() => modelAttributeName(annotation, type));
      expect(ms).toBeLessThan(LIMIT_MS);
    }
    expect(modelAttributeName(annotation, "List<Item>")).toBe("itemList");
    expect(modelAttributeName(annotation, "String")).toBe("string");
  });
});

describe("model-to-view links stay linear (#338 review)", () => {
  const HEAD =
    "import org.springframework.stereotype.Controller;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.web.servlet.mvc.support.RedirectAttributes;\n@Controller\nclass C {\n";
  const parse = async (source: string) => {
    const runtime = new TreeSitterRuntime();
    try {
      const outcome = await runtime.parse("java", source);
      if (outcome.status !== "parsed") throw new Error(outcome.status);
      try {
        return timed(() => analyzeJvmTree(outcome.tree.rootNode, source, "C.java", "java"));
      } finally {
        outcome.dispose();
      }
    } finally {
      runtime.dispose();
    }
  };
  const controller = (handlers: number, models: number): string => {
    let source = HEAD;
    for (let i = 0; i < handlers; i += 1) {
      source += `@GetMapping("/h${i}") String h${i}() { return "v${i}"; }\n`;
    }
    for (let i = 0; i < models; i += 1) {
      source += `@ModelAttribute("b") String b${i}(@RequestParam String b) { return b; }\n`;
    }
    return `${source}}\n`;
  };

  it("many @ModelAttribute methods of one name are one source, not one per method", async () => {
    const few = await parse(controller(400, 20));
    const many = await parse(controller(400, 2000));
    expect(few.value.modelAttributes).toHaveLength(1);
    expect(many.value.modelAttributes).toHaveLength(1);
    // 100x more methods must be far from 100x the time (with a floor for slow runners).
    expect(many.ms).toBeLessThan(Math.max(LIMIT_MS, few.ms * 40));
  });

  it("many flash attributes that lead to the same views are few sources", async () => {
    let source = HEAD;
    for (let i = 0; i < 300; i += 1) {
      source += `@GetMapping("/x/{a}/t${i % 3}") String g${i}() { return "v${i}"; }\n`;
    }
    for (let i = 0; i < 2000; i += 1) {
      source += `@PostMapping("/p${i}") String p${i}(@RequestParam String q, RedirectAttributes ra) { ra.addFlashAttribute("f", q); return "redirect:/x/1/t${i % 3}"; }\n`;
    }
    const { value, ms } = await parse(`${source}}\n`);
    expect(value.modelAttributes.length).toBeLessThanOrEqual(3);
    expect(ms).toBeLessThan(LIMIT_MS * 4);
  });

  it("a template that reads one attribute many times scans the sources once", () => {
    const views = Array.from({ length: 100 }, (_, i) => `v${i}`);
    const sources = Array.from({ length: 3000 }, (_, i) => ({
      path: "C.java",
      line: i,
      views,
      partial: true,
    }));
    const model = new Map([["b", sources]]);
    const page = '<p th:utext="${b}"></p>\n'.repeat(5000);
    const { value, ms } = timed(() => analyzeThymeleaf(page, "templates/other.html", model));
    expect(value.findings.length).toBeGreaterThan(0);
    expect(ms).toBeLessThan(LIMIT_MS * 4);
  });
});

describe("JWT key and Go scope patterns stay linear (#271, #298, #375)", () => {
  it("reads a PEM check on a literal that is one long blank run", () => {
    const code = `import jwt from 'jsonwebtoken'; const KEY = '${" ".repeat(SIZE)}x'; jwt.verify(t, KEY);`;
    const { value, ms } = timed(() => analyzeJsSource(code, "src/a.ts").findings.length);
    expect(value).toBe(1);
    expect(ms).toBeLessThan(LIMIT_MS);
  });

  it("reads Go call sites and signatures built from long runs", () => {
    const longName = "a".repeat(SIZE);
    const blanks = " ".repeat(SIZE);
    const params = Array.from({ length: 20_000 }, (_, index) => `p${index}`).join(", ");
    const sources = [
      `package main\nfunc f() {\n\t${longName}\n}`,
      `package main\nfunc f() {\n\tf${blanks}\n}`,
      `package main\nfunc f(${params} string) {\n\tf(${params})\n}`,
      `package main\nfunc (${blanks}) f${blanks}(${blanks}) {\n}`,
    ];
    for (const source of sources) {
      const { ms } = timed(() => analyzeGoSource(source, "a.go"));
      expect(ms).toBeLessThan(LIMIT_MS);
    }
  });
});
