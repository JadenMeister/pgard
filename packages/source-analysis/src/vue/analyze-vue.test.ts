import { describe, expect, it } from "vitest";
import { analyzeVueSource } from "./analyze-vue.js";

describe("analyzeVueSource", () => {
  it("flags v-html bound to route input with a higher rating than unknown values", () => {
    const { findings } = analyzeVueSource(
      `<template>
  <div>
    <p v-html="$route.query.msg"></p>
    <p v-html="content"></p>
  </div>
</template>
<script setup lang="ts">
const content = props.body;
</script>`,
      "src/Page.vue",
    );
    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      ruleId: "PG-XSS-003",
      line: 3,
      severity: "high",
      confidence: "medium",
    });
    expect(findings[1]).toMatchObject({
      ruleId: "PG-XSS-003",
      line: 4,
      severity: "low",
      confidence: "low",
    });
    for (const finding of findings) expect(finding.status).toBe("suspected");
  });

  it.each([
    [`<template><p v-html="'<b>static</b>'"></p></template>`],
    [
      `<template><p v-html="DOMPurify.sanitize(raw)"></p></template><script setup>import DOMPurify from "dompurify";</script>`,
    ],
    [`<template><p>{{ $route.query.msg }}</p></template>`],
  ])("does not flag static, sanitized or interpolated text: %s", (code) => {
    expect(analyzeVueSource(code, "src/A.vue").findings).toEqual([]);
  });

  it("analyzes script blocks with the JS/TS rules and correct line numbers", () => {
    const { findings, facts } = analyzeVueSource(
      `<template><div /></template>
<script>
import { Pool } from "pg";
export default {
  async load(req) { return pool.query(\`SELECT * FROM t WHERE id = \${req.query.id}\`); }
};
</script>`,
      "src/Legacy.vue",
    );
    expect(findings).toEqual([expect.objectContaining({ ruleId: "PG-SQL-001", line: 5 })]);
    expect(facts?.imports).toContain("pg");
  });

  it("keeps a v-html bound to a sanitizing computed at low confidence, saying why", () => {
    const setup = analyzeVueSource(
      `<template><div v-html="clean"></div></template>
<script setup>
import DOMPurify from "dompurify";
import { computed } from "vue";
const props = defineProps({ html: String });
const clean = computed(() => DOMPurify.sanitize(props.html));
</script>`,
      "src/A.vue",
    );
    expect(setup.findings).toHaveLength(1);
    expect(setup.findings[0]).toMatchObject({ confidence: "low", status: "suspected" });
    expect(setup.findings[0]?.evidence).toContain('computed "clean"');
    const options = analyzeVueSource(
      `<template><div v-html="safe"></div></template>
<script>
import sanitizeHtml from "sanitize-html";
export default { computed: { safe() { return sanitizeHtml(this.html); } } };
</script>`,
      "src/B.vue",
    );
    expect(options.findings[0]?.evidence).toContain('computed "safe"');
    // Only part of the value sanitized, or a sanitizer that is not imported: ordinary finding.
    const partial = analyzeVueSource(
      `<template><div v-html="clean"></div></template>
<script setup>
import DOMPurify from "dompurify";
import { computed } from "vue";
const clean = computed(() => DOMPurify.sanitize(a) + b);
</script>`,
      "src/C.vue",
    );
    expect(partial.findings[0]?.evidence).not.toContain("computed");
    const other = analyzeVueSource(
      `<template><div v-html="clean"></div></template>
<script setup>
import purify from "./purify.js";
import { computed } from "vue";
const clean = computed(() => purify(a));
</script>`,
      "src/E.vue",
    );
    expect(other.findings[0]?.evidence).not.toContain("computed");
    const local = analyzeVueSource(
      `<template><div v-html="clean"></div></template>
<script setup>
import { computed } from "vue";
const DOMPurify = { sanitize: (x) => x };
const clean = computed(() => DOMPurify.sanitize(a));
</script>`,
      "src/D.vue",
    );
    expect(local.findings[0]?.evidence).not.toContain("computed");
  });

  it("reports parse errors instead of throwing", () => {
    expect(analyzeVueSource("<template><div></template", "src/B.vue").hasParseErrors).toBe(true);
  });

  describe("sanitizers are trusted only through an import binding (#272)", () => {
    const vhtml = (expression: string, script: string) =>
      analyzeVueSource(
        `<template><div v-html="${expression}"></div></template>\n<script setup>\n${script}\n</script>`,
        "src/V.vue",
      ).findings.filter((finding) => finding.ruleId === "PG-XSS-003");
    const NOTE = "is not a known sanitizer import; inferred";

    it.each([
      ["a Vue method", "purify(html)", "export default {};"],
      ["a local function", "sanitize(html)", "function sanitize(s) { return s; }"],
      ["a local arrow", "sanitize($route.query.b)", "const sanitize = (s) => s;"],
      ["a global", "DOMPurify.sanitize(html)", ""],
      ["a local-module re-export", "sanitize(html)", "import { sanitize } from '@/utils';"],
      ["an unrelated package", "sanitize(html)", "import { sanitize } from 'lodash';"],
      [
        "a shadowed import",
        "DOMPurify.sanitize(html)",
        "import DOMPurify from 'dompurify';\nfunction f(DOMPurify) { return DOMPurify; }",
      ],
      [
        "a reassigned import",
        "DOMPurify.sanitize(html)",
        "import DOMPurify from 'dompurify';\nDOMPurify = { sanitize: (s) => s };",
      ],
    ])("demotes %s", (_label, expression, script) => {
      const [finding, ...rest] = vhtml(expression, script);
      expect(rest).toEqual([]);
      expect(finding?.confidence).toBe("low");
      expect(["low", "medium"]).toContain(finding?.severity);
      expect(finding?.evidence).toContain(NOTE);
    });

    it("caps route input behind a name-only sanitizer at medium", () => {
      const [finding] = vhtml("sanitize($route.query.b)", "const sanitize = (s) => s;");
      expect(finding).toMatchObject({ severity: "medium", confidence: "low" });
    });

    it.each([
      ["dompurify", "DOMPurify.sanitize(html)", "import DOMPurify from 'dompurify';"],
      [
        "isomorphic-dompurify",
        "purify.sanitize(html)",
        "import purify from 'isomorphic-dompurify';",
      ],
      ["sanitize-html", "clean(html)", "import clean from 'sanitize-html';"],
      ["xss", "filterXSS(html)", "import { filterXSS } from 'xss';"],
      ["xss-filters", "xssFilters.inHTMLData(html)", "import xssFilters from 'xss-filters';"],
    ])("fully suppresses the sole import of %s", (_label, expression, script) => {
      expect(vhtml(expression, script)).toEqual([]);
    });

    it("does not fully trust escape-html, and not a sanitized value mixed with more", () => {
      const [escaped] = vhtml("escapeHtml(html)", "import escapeHtml from 'escape-html';");
      expect(escaped?.confidence).toBe("low");
      expect(escaped?.evidence).toContain("escape-html");
      const [mixed] = vhtml("DOMPurify.sanitize(a) + b", "import DOMPurify from 'dompurify';");
      expect(mixed).toBeDefined();
    });

    it.each([
      [
        "a config getter",
        "DOMPurify.getConfig($route.query.q)",
        "import DOMPurify from 'dompurify';",
      ],
      [
        "an xss-filters attribute filter",
        "xssFilters.inDoubleQuotedAttr($route.query.q)",
        "import xssFilters from 'xss-filters';",
      ],
      [
        "a modified import",
        "DOMPurify.sanitize($route.query.q)",
        "import DOMPurify from 'dompurify';\nDOMPurify.sanitize = (s) => s;",
      ],
      [
        "an import re-declared by a function",
        "DOMPurify.sanitize($route.query.q)",
        "import DOMPurify from 'dompurify';\nfunction DOMPurify() {}",
      ],
    ])("does not trust %s", (_label, expression, script) => {
      const [finding] = vhtml(expression, script);
      expect(finding).toBeDefined();
      expect(finding?.severity === "high" || finding?.confidence === "low").toBe(true);
      if (finding?.confidence === "low") expect(finding.evidence).toContain(NOTE);
    });

    it("keeps xssFilters.inDoubleQuotedAttr at high severity and trusts inHTMLData", () => {
      expect(
        vhtml(
          "xssFilters.inDoubleQuotedAttr($route.query.q)",
          "import xssFilters from 'xss-filters';",
        )[0],
      ).toMatchObject({ severity: "high", confidence: "medium" });
      expect(vhtml("xssFilters.inHTMLData(html)", "import xssFilters from 'xss-filters';")).toEqual(
        [],
      );
    });

    it("does not count imports of a plain options-API <script> as proof for the template", () => {
      const result = analyzeVueSource(
        `<template><div v-html="DOMPurify.sanitize(html)"></div></template>
<script>
import DOMPurify from "dompurify";
export default { props: { html: String } };
</script>`,
        "src/O.vue",
      ).findings.filter((finding) => finding.ruleId === "PG-XSS-003");
      expect(result[0]?.confidence).toBe("low");
      expect(result[0]?.evidence).toContain(NOTE);
    });

    it("does not treat a sanitizer applied to part of the value as covering all of it", () => {
      const [finding] = vhtml(
        "DOMPurify.sanitize(a) + $route.query.b",
        "import DOMPurify from 'dompurify';",
      );
      expect(finding?.severity).toBe("medium");
    });
  });
});
