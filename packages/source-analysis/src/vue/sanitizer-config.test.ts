import { describe, expect, it } from "vitest";
import { analyzeVueSource } from "./analyze-vue.js";

const DOMPURIFY = 'import DOMPurify from "dompurify";';
const vue = (template: string, script: string) =>
  analyzeVueSource(
    `<template>${template}</template>\n<script setup>\n${script}\n</script>`,
    "src/V.vue",
  ).findings.filter((finding) => finding.ruleId === "PG-XSS-003");
const plain = '<div v-html="DOMPurify.sanitize(html)"></div>';

describe("Vue v-html and sanitizer configuration (#278)", () => {
  it("still suppresses a plain DOMPurify.sanitize", () => {
    expect(vue(plain, DOMPURIFY)).toEqual([]);
  });

  it.each([
    ["an addHook in the script", `${DOMPURIFY}\nDOMPurify.addHook("afterSanitizeAttributes", f);`],
    ["a risky setConfig", `${DOMPURIFY}\nDOMPurify.setConfig({ ADD_TAGS: ["script"] });`],
  ])("demotes, not drops, a sanitize call with %s", (_label, script) => {
    const [finding, ...rest] = vue(plain, script);
    expect(rest).toEqual([]);
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain("script or event handlers");
  });

  it.each([
    ["ADD_TAGS with script", "DOMPurify.sanitize(html, { ADD_TAGS: ['script'] })"],
    ["RETURN_DOM_FRAGMENT", "DOMPurify.sanitize(html, { RETURN_DOM_FRAGMENT: true })"],
    ["a named options object", "DOMPurify.sanitize(html, cfg)"],
  ])("demotes a template call with %s", (_label, expression) => {
    const [finding] = vue(`<div v-html="${expression}"></div>`, DOMPURIFY);
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain("script or event handlers");
  });

  it("keeps a template call with harmless options suppressed", () => {
    expect(
      vue("<div v-html=\"DOMPurify.sanitize(html, { ADD_ATTR: ['target'] })\"></div>", DOMPURIFY),
    ).toEqual([]);
  });
});

describe("Vue template-local names that shadow the sanitizer (#278)", () => {
  const NOTE = "is not a known sanitizer import; inferred";

  it.each([
    [
      "a v-for alias",
      '<div v-for="DOMPurify in helpers" :key="1"><span v-html="DOMPurify.sanitize(html)"></span></div>',
    ],
    [
      "a v-for alias in a tuple",
      '<div v-for="(DOMPurify, i) of helpers" :key="i"><span v-html="DOMPurify.sanitize(html)"></span></div>',
    ],
    [
      "a v-for alias on the same element",
      '<div v-for="DOMPurify in helpers" :key="1" v-html="DOMPurify.sanitize(html)"></div>',
    ],
    [
      "a destructured slot prop",
      '<Comp v-slot="{ DOMPurify }"><span v-html="DOMPurify.sanitize(html)"></span></Comp>',
    ],
    [
      "a shorthand slot prop",
      '<Comp><template #default="{ DOMPurify }"><span v-html="DOMPurify.sanitize(html)"></span></template></Comp>',
    ],
    [
      "a slot-scope attribute",
      '<Comp><template slot-scope="DOMPurify"><span v-html="DOMPurify.sanitize(html)"></span></template></Comp>',
    ],
  ])("does not prove the import under %s", (_label, template) => {
    const [finding, ...rest] = vue(template, DOMPURIFY);
    expect(rest).toEqual([]);
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain(NOTE);
  });

  it("keeps the import proven outside the shadowing subtree and for other names", () => {
    expect(
      vue(
        '<div><p v-for="x in list" :key="x"></p><Comp v-slot="{ item }"><span v-html="DOMPurify.sanitize(item)"></span></Comp><span v-html="DOMPurify.sanitize(html)"></span></div>',
        DOMPURIFY,
      ),
    ).toEqual([]);
    const [outside] = vue(
      '<div><p v-for="DOMPurify in list" :key="1"></p><span v-html="DOMPurify.sanitize(html)"></span></div>',
      DOMPURIFY,
    );
    expect(outside).toBeUndefined();
  });

  it.each([
    ["a props array", "export default { props: ['DOMPurify'] };"],
    ["a props object", "export default { props: { DOMPurify: Object } };"],
    ["a data key", "export default { data() { return { DOMPurify: {} }; } };"],
    ["a methods key", "export default { methods: { DOMPurify() {} } };"],
    ["a computed key", "export default { computed: { DOMPurify() { return 1; } } };"],
    ["defineProps", "defineProps({ DOMPurify: Object });"],
    ["a destructured declaration", "const { DOMPurify: _x, other: DOMPurify } = obj;"],
  ])("does not prove the import when %s declares the same name", (_label, extra) => {
    const [finding] = vue(plain, `${DOMPURIFY}\n${extra}`);
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain(NOTE);
  });

  it("does not prove the import when a typed defineProps declares the same name", () => {
    const [finding] = analyzeVueSource(
      `<template>${plain}</template>\n<script setup lang="ts">\n${DOMPURIFY}\ndefineProps<{ DOMPurify: object }>();\n</script>`,
      "src/V.vue",
    ).findings;
    expect(finding?.confidence).toBe("low");
  });

  it("keeps the import proven when an options key has another name", () => {
    expect(
      vue(plain, `${DOMPURIFY}\nexport default { props: ['html'], data() { return { a: 1 }; } };`),
    ).toEqual([]);
  });

  it("stays bounded on a deep template and many aliases", () => {
    const deep = `${"<div>".repeat(300)}<span v-html="html"></span>${"</div>".repeat(300)}`;
    expect(vue(deep, DOMPURIFY).length).toBe(1);
    const aliases = Array.from({ length: 300 }, (_, i) => `a${i}`).join(", ");
    const started = Date.now();
    vue(`<div v-for="(${aliases}) in list" :key="1"><i v-html="html"></i></div>`, DOMPURIFY);
    expect(Date.now() - started).toBeLessThan(2000);
  });
});
