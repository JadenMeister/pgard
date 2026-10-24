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
    [`<template><p v-html="DOMPurify.sanitize(raw)"></p></template>`],
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

  it("reports parse errors instead of throwing", () => {
    expect(analyzeVueSource("<template><div></template", "src/B.vue").hasParseErrors).toBe(true);
  });
});
