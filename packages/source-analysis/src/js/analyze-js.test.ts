import { describe, expect, it } from "vitest";
import { analyzeVueSource } from "../vue/analyze-vue.js";
import { analyzeJsSource } from "./analyze-js.js";

const rulesIn = (code: string, path = "src/app.ts") =>
  analyzeJsSource(code, path).findings.map((finding) => finding.ruleId);
const findingsIn = (code: string, path = "src/app.ts") => analyzeJsSource(code, path).findings;

/** Slow Windows runners get three times the room; elsewhere the limits stay tight. */
const SLOW = process.platform === "win32" ? 3 : 1;

/** Fastest of `runs` timings in ms: one run is noisy when other test files run in parallel. */
const bestTimeOf = (runs: number, fn: () => void) => {
  let best = Infinity;
  for (let run = 0; run < runs; run += 1) {
    const start = performance.now();
    fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
};

describe("PG-SQL-001 pg/mysql2", () => {
  it("flags request input interpolated into pool.query", () => {
    const [finding] = findingsIn(`
      import { Pool } from "pg";
      const pool = new Pool();
      app.get("/u", async (req, res) => {
        const rows = await pool.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);
      });
    `);
    expect(finding).toMatchObject({
      ruleId: "PG-SQL-001",
      severity: "high",
      status: "confirmed",
      line: 5,
    });
  });

  it("flags concatenation through a variable (suspected)", () => {
    const [finding] = findingsIn(`
      import mysql from "mysql2/promise";
      export async function find(req, conn) {
        const name = req.body.name;
        const sql = "SELECT * FROM t WHERE name = '" + name + "'";
        return conn.execute(sql);
      }
    `);
    expect(finding).toMatchObject({ ruleId: "PG-SQL-001", severity: "high", status: "suspected" });
  });

  it("flags SQL text built dynamically even without a driver import", () => {
    expect(rulesIn("db.query(`SELECT * FROM t WHERE x = ${value}`);")).toEqual(["PG-SQL-001"]);
  });

  it.each([
    ['import { Pool } from "pg"; pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);'],
    ['import mysql from "mysql2"; conn.execute("SELECT * FROM t WHERE a = ?", [req.body.a]);'],
    ['import { Pool } from "pg"; pool.query({ text: "SELECT 1 WHERE id = $1", values: [id] });'],
    ["const result = items.query(`${a}`);"],
    ['import { Pool } from "pg"; const sql = "SELECT 1"; pool.query(sql);'],
  ])("does not flag parameter binding or static SQL: %s", (code) => {
    expect(rulesIn(code)).not.toContain("PG-SQL-001");
  });
});

describe("PG-SQL-002 Prisma", () => {
  it("flags $queryRawUnsafe with interpolation", () => {
    expect(
      rulesIn("await prisma.$queryRawUnsafe(`SELECT * FROM u WHERE id = ${req.params.id}`);"),
    ).toEqual(["PG-SQL-002"]);
  });

  it("flags Prisma.raw with dynamic SQL", () => {
    expect(rulesIn("prisma.$queryRaw(Prisma.raw('SELECT * FROM ' + table));")).toEqual([
      "PG-SQL-002",
    ]);
  });

  it.each([
    ["await prisma.$queryRaw`SELECT * FROM u WHERE id = ${req.params.id}`;"],
    ['await prisma.$queryRawUnsafe("SELECT * FROM u WHERE id = $1", req.params.id);'],
    ["await prisma.$executeRaw(Prisma.sql`DELETE FROM u WHERE id = ${id}`);"],
  ])("does not flag tagged templates or bound parameters: %s", (code) => {
    expect(rulesIn(code)).toEqual([]);
  });
});

describe("PG-XSS jQuery, escape-html, bundled templates and spread props", () => {
  const xss = (code: string, path = "src/app.js") =>
    findingsIn(code, path).filter((finding) => finding.ruleId.startsWith("PG-XSS-"));

  it("flags jQuery .html() and HTML-building inserters, not text, selectors or elements", () => {
    const h = (body: string) => xss(`import $ from "jquery"; ${body}`);
    expect(h('$("#o").html("<b>" + location.hash + "</b>");')).toHaveLength(1);
    expect(
      h('$("#o").find("p").html(`<i>${new URLSearchParams(location.search).get("q")}</i>`);'),
    ).toHaveLength(1);
    expect(h('const $o = $("#o"); $o.html(data);')).toHaveLength(1);
    expect(h('$("#o").append("<li>" + item.name + "</li>");')).toHaveLength(1);
    expect(h('$("#o").before(`<hr>${title}`);')).toHaveLength(1);
    expect(h("$(location.hash).hide();")).toHaveLength(1);
    expect(h('$("<div>" + name + "</div>").appendTo("#o");')).toHaveLength(1);
    // Not sinks: text, selector building, a node, a static string, a function, the getter.
    expect(h('$("#o").text(location.hash); $("#row-" + id).show();')).toEqual([]);
    expect(h('$("#o").append(node); $("#o").append(document.createTextNode(name));')).toEqual([]);
    expect(h('$("#o").html("<b>Saved</b>"); $("<div>"); $("#o").html();')).toEqual([]);
    expect(h('$("#o").html(function (i, old) { return old; });')).toEqual([]);
    expect(h('$("#o").html(DOMPurify.sanitize(data));')).toEqual([]);
    // A `$` that is not jQuery: cheerio, or a local helper.
    expect(
      xss('const cheerio = require("cheerio"); const $ = cheerio.load(page); $("t").html(title);'),
    ).toEqual([]);
    expect(xss("const $ = (s) => document.querySelector(s); $('#o').html(x);")).toEqual([]);
    // An IIFE parameter named $ is jQuery.
    expect(xss("(function ($) { $('#o').html('<b>' + location.hash); })(jQuery);")).toHaveLength(1);
  });

  it("never silences a value that goes through escape-html, and words the evidence by context", () => {
    const e = (body: string) => xss(`import esc from "escape-html"; ${body}`);
    const looksLikeText = [
      "el.innerHTML = `<b>${esc(a)}</b> <i>${esc(b)}</i>`;",
      "el.innerHTML = `<ul><li>${esc(a)} ${5}</li></ul>`;",
      "const OPEN = '<p class=\"x\">'; el.innerHTML = OPEN + esc(a) + '</p>';",
      "$('#o').html('<p>' + esc(a) + '</p>');",
      // Nested inside raw text it cannot see: still reported, wording asks to verify.
      "el.innerHTML = `<script><b>${esc(u)}`;",
    ];
    for (const body of looksLikeText) {
      const found = e(body);
      expect(found, body).toHaveLength(1);
      expect(found[0], body).toMatchObject({ confidence: "low", status: "suspected" });
      expect(found[0]?.severity, body).not.toBe("high");
      expect(found[0]?.evidence, body).toContain("looks like an HTML text context");
    }
    const notSufficient = [
      "el.innerHTML = `<a href=${esc(u)}>x</a>`;",
      'el.innerHTML = `<a href="${esc(u)}">x</a>`;',
      'el.innerHTML = `<a title="t" onclick="${esc(u)}">x</a>`;',
      'el.innerHTML = `<meta http-equiv="refresh" content="0;url=${esc(u)}">`;',
      'el.innerHTML = `<svg><animate attributeName="href" values="${esc(u)}"/></svg>`;',
      "el.innerHTML = `<script>var x = '${esc(u)}'</script>`;",
      "el.innerHTML = `<script/>${esc(u)}`;",
      "el.innerHTML = `<style><i>x</i>${esc(u)}`;",
      "el.innerHTML = `<textarea>${esc(u)}</textarea>`;",
      "el.innerHTML = esc(u);",
      "$('#o').html(esc(u));",
      "const OPEN_LINK = '<a href=\"'; el.innerHTML = OPEN_LINK + esc(u) + '\">x</a>';",
      "document.createElement('script').innerHTML = esc(u);",
    ];
    for (const body of notSufficient) {
      const found = e(body);
      expect(found, body).toHaveLength(1);
      expect(found[0], body).toMatchObject({ confidence: "low", status: "suspected" });
      expect(found[0]?.severity, body).not.toBe("high");
      expect(found[0]?.evidence, body).toContain("not sufficient");
    }
    // A void-element prefix is never a reason to stay silent.
    const voided = e('el.innerHTML = "<img src=x>" + esc(a);');
    expect(voided).toHaveLength(1);
    expect(voided[0]).toMatchObject({ confidence: "low" });
    // A part that is not escape-html's keeps the normal medium-or-higher finding, even when the
    // file imports escape-html and the sink also has an escaped part.
    expect(e("el.innerHTML = `<b>${esc(a)}</b>${location.hash}`;")[0]).toMatchObject({
      confidence: "medium",
    });
    expect(
      xss(
        'import esc from "escape-html"; import t from "./t.js"; el.innerHTML = "<b>" + t(location.hash);',
      )[0],
    ).toMatchObject({ confidence: "medium" });
    // Not the escape-html module (a local function, a shadowing parameter, another import).
    for (const body of [
      "function esc(s) { return s; } el.innerHTML = `<b>${esc(location.hash)}</b>`;",
      "function f(esc) { el.innerHTML = `<b>${esc(location.hash)}</b>`; }",
    ])
      expect(xss(`import esc from "escape-html"; ${body}`)[0], body).toMatchObject({
        confidence: "medium",
      });
    for (const module of ["./html-utils.js", "lodash"])
      expect(
        xss(`import esc from "${module}"; el.innerHTML = \`<b>\${esc(location.hash)}</b>\`;`)[0],
        module,
      ).toMatchObject({ confidence: "medium" });
  });

  it("stays linear in the number of escape-html parts", () => {
    const parts = Array.from({ length: 4000 }, () => "<li>${esc(a)}</li>").join("");
    const code = `import esc from "escape-html"; el.innerHTML = \`${parts}\`;`;
    const start = performance.now();
    expect(xss(code)).toHaveLength(1);
    expect(performance.now() - start).toBeLessThan(1500);
  });

  it("does not treat a jQuery or DOM node result as an HTML string", () => {
    const h = (body: string) => xss(`import $ from "jquery"; ${body}`);
    expect(h('$("#list").append($("<li>").text(location.hash));')).toEqual([]);
    expect(h('$("#list").append($("<li>").attr("title", location.hash));')).toEqual([]);
    expect(h('$("#list").append(document.createElement("li"));')).toEqual([]);
    expect(h('$("#list").append("<li>" + location.hash + "</li>");')).toHaveLength(1);
  });

  it("demotes an imported bundled template instead of dropping the finding", () => {
    for (const module of ["./card.html?raw", "../views/card.html", "./logo.svg?inline"]) {
      const [finding] = xss(`import tpl from "${module}"; el.innerHTML = tpl;`, "src/a.ts");
      expect(finding, module).toMatchObject({ confidence: "low", status: "suspected" });
      expect(finding?.evidence).toContain("build-time asset");
    }
    const [plain] = xss('import tpl from "./render.js"; el.innerHTML = tpl;');
    expect(plain?.evidence).not.toContain("build-time asset");
  });

  it("follows dangerouslySetInnerHTML through spread props and createElement", () => {
    const j = (body: string) => xss(body, "src/a.jsx").map((finding) => finding.ruleId);
    expect(
      j("const p = { dangerouslySetInnerHTML: { __html: html } }; const A = () => <div {...p} />;"),
    ).toEqual(["PG-XSS-002"]);
    expect(
      j("const A = () => <div {...{ dangerouslySetInnerHTML: { __html: html } }} />;"),
    ).toEqual(["PG-XSS-002"]);
    expect(
      j(
        "const markup = { __html: html }; const A = () => <div {...{ dangerouslySetInnerHTML: markup }} />;",
      ),
    ).toEqual(["PG-XSS-002"]);
    expect(
      j(
        'const A = () => React.createElement("div", { dangerouslySetInnerHTML: { __html: html } });',
      ),
    ).toEqual(["PG-XSS-002"]);
    expect(
      j(
        'const p = { dangerouslySetInnerHTML: { __html: "<b>x</b>" } }; const A = () => <div {...p} />;',
      ),
    ).toEqual([]);
    expect(
      j(
        "const p = { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(h) } }; const A = () => <div {...p} />;",
      ),
    ).toEqual([]);
    expect(j("const A = ({ ...rest }) => <div {...rest} className='a' />;")).toEqual([]);
    // Reassigned or shadowed spread objects are not resolved.
    expect(j("let p = {}; p = other; const A = () => <div {...p} />;")).toEqual([]);
  });
});

describe("PG-XSS-001/002 HTML sinks", () => {
  it("rates request/browser input into innerHTML higher than unknown values", () => {
    const [fromInput] = findingsIn("el.innerHTML = location.search;");
    const [unknown] = findingsIn("el.innerHTML = html;");
    expect(fromInput).toMatchObject({
      ruleId: "PG-XSS-001",
      severity: "high",
      confidence: "medium",
      status: "suspected",
    });
    expect(unknown).toMatchObject({
      ruleId: "PG-XSS-001",
      severity: "low",
      confidence: "low",
      status: "suspected",
    });
  });

  it("never marks API use alone as confirmed", () => {
    for (const finding of findingsIn("el.innerHTML = `<b>${name}</b>`; document.write(x);")) {
      expect(finding.status).toBe("suspected");
    }
  });

  it.each([
    ['el.innerHTML = "<b>static</b>";'],
    ["el.innerHTML = `<b>static</b>`;"],
    ["el.innerHTML = DOMPurify.sanitize(req.body.html);"],
    ["el.textContent = req.body.html;"],
  ])("does not flag static or sanitized HTML: %s", (code) => {
    expect(rulesIn(code)).toEqual([]);
  });

  it("flags dangerouslySetInnerHTML with dynamic HTML", () => {
    const findings = findingsIn(
      "export const A = ({ q }) => <div dangerouslySetInnerHTML={{ __html: useSearchParams()[0].get('q') }} />;",
      "src/A.tsx",
    );
    expect(findings[0]).toMatchObject({ ruleId: "PG-XSS-002", severity: "high" });
  });

  it("does not flag dangerouslySetInnerHTML with a literal or sanitizer", () => {
    expect(
      rulesIn(
        'const A = () => <><i dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} /><i dangerouslySetInnerHTML={{ __html: sanitize(x) }} /></>;',
        "src/A.jsx",
      ),
    ).toEqual([]);
  });

  it.each([
    ["const clean = DOMPurify.sanitize(req.body.html);\nel.innerHTML = clean;"],
    ["export {};\nlet html;\nhtml = DOMPurify.sanitize(input);\nel.innerHTML = html;"],
    ["function f() {\n  var h = DOMPurify.sanitize(a);\n  el.innerHTML = h;\n}"],
    [
      "const safe = sanitizeHtml(data);\nconst A = () => <i dangerouslySetInnerHTML={{ __html: safe }} />;",
    ],
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\nif (c) { h = DOMPurify.sanitize(b); }\nel.innerHTML = h;",
    ],
    ["export {};\nlet h = DOMPurify.sanitize(a);\nh ||= DOMPurify.sanitize(b);\nel.innerHTML = h;"],
    ["const h = DOMPurify.sanitize(a);\nfunction f() { var h = req.body.x; }\nel.innerHTML = h;"],
    ["export {};\nfunction f() { el.innerHTML = h; }\nvar h;\nh = DOMPurify.sanitize(a);"],
    ["export let h = DOMPurify.sanitize(a);\nel.innerHTML = h;"],
    ["const h = DOMPurify.sanitize(a);\nel.outerHTML = h;\nel.insertAdjacentHTML('beforeend', h);"],
  ])("does not flag a value sanitized through a variable (#109): %s", (code) => {
    expect(rulesIn(code, "src/a.tsx")).toEqual([]);
  });

  it.each([
    // Plain, branch and closure reassignment.
    ["let html = DOMPurify.sanitize(a);\nhtml = req.body.html;\nel.innerHTML = html;"],
    ["let h = DOMPurify.sanitize(a);\nif (c) { h = req.body.x; }\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nconst set = (v) => { h = v; };\nel.innerHTML = h;"],
    // Compound and logical assignment operators.
    ["let h = DOMPurify.sanitize(a);\nh += req.body.x;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nh ||= req.body.html;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nh ??= req.query.x;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nh &&= req.body.html;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nh ||= location.hash;\nel.outerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nh ??= req.body.x;\nel.insertAdjacentHTML('beforeend', h);"],
    // for-in / for-of targets without a declaration, and a classic for initializer.
    ["let h = DOMPurify.sanitize(a);\nfor (h of req.body.items) el.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nfor (h in req.body) el.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nfor (h = req.body.x; ;) break;\nel.innerHTML = h;"],
    ["const html = DOMPurify.sanitize(a);\nfor (const html of items) el.innerHTML = html;"],
    // Scope: globals, imports, functions, classes, parameters, inner shadowing, catch.
    ["function g(a) { const name = DOMPurify.sanitize(a); use(name); }\nel.innerHTML = name;"],
    [
      "import { h } from './x';\nfunction g(a) { const h = DOMPurify.sanitize(a); use(h); }\nel.innerHTML = h;",
    ],
    ["function g() { const h = DOMPurify.sanitize(a); }\nfunction h() {}\nel.innerHTML = h;"],
    ["function g() { const h = DOMPurify.sanitize(a); }\nclass h {}\nel.innerHTML = h;"],
    ["const html = DOMPurify.sanitize(a);\nfunction f(html) { el.innerHTML = html; }"],
    ["const h = DOMPurify.sanitize(a);\nfunction f() { let h; el.innerHTML = h; }"],
    ["const e = DOMPurify.sanitize(a);\ntry {} catch (e) { el.innerHTML = e; }"],
    [
      "const safe = DOMPurify.sanitize(a);\nconst A = ({ safe }) => <i dangerouslySetInnerHTML={{ __html: safe }} />;",
    ],
    // Destructuring declarations and assignments.
    [
      "const html = DOMPurify.sanitize(a);\nfunction f() { const { html } = data; el.innerHTML = html; }",
    ],
    ["let h = DOMPurify.sanitize(a);\n({ h } = req.body);\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\n[h] = req.body.list;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\n({ x: { y: h } } = req.body);\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\n[...h] = req.body.list;\nel.innerHTML = h;"],
    [
      "let h = DOMPurify.sanitize(a);\n[h = DOMPurify.sanitize(b)] = req.body.list;\nel.innerHTML = h;",
    ],
    // Object properties, exported bindings and dynamic scope.
    ["const o = {};\no.h = DOMPurify.sanitize(a);\no.h = req.body.x;\nel.innerHTML = o.h;"],
    [
      "export let h = DOMPurify.sanitize(a);\nexport function setH(v) { h = v; }\nel.innerHTML = h;",
    ],
    ["let h = DOMPurify.sanitize(a);\neval('h = req.body.x');\nel.innerHTML = h;"],
    // Writes through type assertions and non-null assertions.
    ["let h = DOMPurify.sanitize(a);\n(h as any) = req.body.x;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nh! = req.body.x;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\n(h satisfies string) = req.body.x;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\n((h as any)!) ||= req.body.x;\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\n[(h as any)] = req.body.list;\nel.innerHTML = h;"],
    // Top-level var/let of a classic script: other scripts and the global object can write it.
    ["var h = DOMPurify.sanitize(a);\nwindow.h = req.body.x;\nel.innerHTML = h;"],
    ["var h = DOMPurify.sanitize(a);\nglobalThis['h'] = req.body.x;\nel.innerHTML = h;"],
    ["var h = DOMPurify.sanitize(a);\nthis.h = req.body.x;\nel.innerHTML = h;"],
    [
      "var h = DOMPurify.sanitize(a);\nObject.defineProperty(window, 'h', { get() { return location.hash; } });\nel.innerHTML = h;",
    ],
    ["if (c) { var h = DOMPurify.sanitize(a); }\nel.innerHTML = h;"],
    ["let h = DOMPurify.sanitize(a);\nel.innerHTML = h;"],
    // Indirect eval, Function and string timers.
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\n(0, eval)('h = location.hash');\nel.innerHTML = h;",
    ],
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\nwindow.eval('h = location.hash');\nel.innerHTML = h;",
    ],
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\nnew Function('h = location.hash')();\nel.innerHTML = h;",
    ],
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\nFunction('h = location.hash')();\nel.innerHTML = h;",
    ],
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\nsetTimeout('h = location.hash');\nel.innerHTML = h;",
    ],
    [
      "export {};\nlet h = DOMPurify.sanitize(a);\nwindow.setInterval(code, 10);\nel.innerHTML = h;",
    ],
  ])("still flags a variable not sanitized on every write (#109): %s", (code) => {
    expect(rulesIn(code, "src/a.tsx").some((rule) => rule.startsWith("PG-XSS-"))).toBe(true);
  });

  it("flags a write through an angle-bracket type assertion in a .ts file (#109)", () => {
    expect(
      rulesIn(
        "export {};\nlet h = DOMPurify.sanitize(a);\n(<any>h) = req.body.x;\nel.innerHTML = h;",
      ),
    ).toContain("PG-XSS-001");
  });

  it("flags a write through a type assertion in a .vue script (#109)", () => {
    const vue = analyzeVueSource(
      '<script lang="ts">\nexport {};\nlet h = DOMPurify.sanitize(a);\n(h as any) = req.body.x;\nel.innerHTML = h;\n</script>\n',
      "A.vue",
    );
    expect(vue.findings.map((finding) => finding.ruleId)).toContain("PG-XSS-001");
  });

  it("resolves bindings in a file with a non-JS extension (#109)", () => {
    expect(
      rulesIn("let h = DOMPurify.sanitize(a);\nh ||= req.body.html;\nel.innerHTML = h;", "A.vue"),
    ).toContain("PG-XSS-001");
  });
});

describe("PG-SSRF-001", () => {
  it.each([
    ["app.get('/p', async (req, res) => { await fetch(req.query.url); });"],
    ["import axios from 'axios'; const target = req.body.target; axios.get(target);"],
    ["import axios from 'axios'; axios({ url: req.query.u, method: 'get' });"],
  ])("flags request input as an outbound URL: %s", (code) => {
    expect(rulesIn(code)).toContain("PG-SSRF-001");
  });

  it.each([
    ["fetch('https://api.example.com/x');"],
    ["fetch(`https://api.example.com/items/${id}`);"],
    ["fetch(location.search);"],
  ])("does not flag fixed URLs or browser-only input: %s", (code) => {
    expect(rulesIn(code)).not.toContain("PG-SSRF-001");
  });
});

describe("PG-CMD-001", () => {
  it("flags exec with request input as critical", () => {
    const [finding] = findingsIn(
      "import { exec } from 'child_process'; exec(`ping ${req.query.host}`);",
    );
    expect(finding).toMatchObject({
      ruleId: "PG-CMD-001",
      severity: "critical",
      status: "confirmed",
    });
  });

  it("flags execSync on a namespace import with a dynamic string", () => {
    expect(
      rulesIn("const cp = require('node:child_process'); cp.execSync('tar -xf ' + file);"),
    ).toEqual(["PG-CMD-001"]);
  });

  it("flags spawn with shell: true and request input", () => {
    expect(
      rulesIn(
        "import { spawn } from 'child_process'; spawn('ls ' + req.query.dir, { shell: true });",
      ),
    ).toEqual(["PG-CMD-001"]);
  });

  it.each([
    ["import { exec } from 'child_process'; exec('ls -la');"],
    ["import { execFile } from 'child_process'; execFile('git', ['log', req.query.ref]);"],
    ["const m = /x/.exec(input); regex.exec(req.body.text);"],
    ["import { spawn } from 'child_process'; spawn('ls', [dir]);"],
  ])("does not flag static commands, argument arrays or unrelated exec: %s", (code) => {
    expect(rulesIn(code)).toEqual([]);
  });
});

describe("PG-PATH-001", () => {
  it.each([
    ["import fs from 'fs'; fs.readFile(req.query.file, cb);"],
    [
      "import { readFileSync } from 'node:fs'; import path from 'path'; readFileSync(path.join(__dirname, req.params.name));",
    ],
    ["app.get('/d', (req, res) => res.download(`/files/${req.query.f}`));"],
  ])("flags request input reaching file reads: %s", (code) => {
    expect(rulesIn(code)).toContain("PG-PATH-001");
  });

  it.each([
    [
      "import fs from 'fs'; import path from 'path'; fs.readFile(path.basename(req.query.file), cb);",
    ],
    ["res.sendFile(req.params.name, { root: '/srv/public' });"],
    ["import fs from 'fs'; fs.readFile('config.json', cb);"],
  ])("does not flag basename, rooted sendFile or fixed paths: %s", (code) => {
    expect(rulesIn(code)).not.toContain("PG-PATH-001");
  });
});

describe("PG-CRYPTO rules", () => {
  it("flags MD5/SHA-1 of passwords only", () => {
    expect(
      rulesIn(
        "import crypto from 'crypto'; const h = crypto.createHash('md5').update(password).digest('hex');",
      ),
    ).toEqual(["PG-CRYPTO-001"]);
    expect(
      rulesIn(
        "import crypto from 'crypto'; const etag = crypto.createHash('sha1').update(body).digest('hex');",
      ),
    ).toEqual([]);
    expect(
      rulesIn("import crypto from 'crypto'; crypto.createHash('sha256').update(password);"),
    ).toEqual([]);
  });

  it("flags hardcoded keys and secrets without echoing them", () => {
    const findings = findingsIn(`
      import crypto from "crypto";
      import jwt from "jsonwebtoken";
      const c = crypto.createCipheriv("aes-256-gcm", "0123456789abcdef0123456789abcdef", iv);
      const t = jwt.sign(payload, "my-jwt-signing-value");
      const v = jwt.verify(token, process.env.JWT_SECRET || "fallback-value");
    `);
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "PG-CRYPTO-002",
      "PG-CRYPTO-002",
      "PG-CRYPTO-002",
    ]);
    expect(findings[2]).toMatchObject({ severity: "medium", status: "suspected" });
    const text = JSON.stringify(findings);
    expect(text).not.toContain("0123456789abcdef");
    expect(text).not.toContain("my-jwt-signing-value");
    expect(text).not.toContain("fallback-value");
  });

  it("does not flag keys loaded from the environment", () => {
    expect(
      rulesIn(
        "import jwt from 'jsonwebtoken'; jwt.sign(p, process.env.JWT_SECRET); crypto.createCipheriv('aes-256-gcm', key, iv);",
      ),
    ).toEqual([]);
  });

  it("resolves an algorithm or cipher name held in a sole-binding constant", () => {
    const hash = (decl: string, rest = "") =>
      rulesIn(
        `import crypto from 'crypto'; ${decl} ${rest} crypto.createHash(ALGORITHM).update(password);`,
      );
    expect(hash("const ALGORITHM = 'md5';")).toEqual(["PG-CRYPTO-001"]);
    expect(hash("const ALGORITHM = `sha1`;")).toEqual(["PG-CRYPTO-001"]);
    expect(hash("const ALGORITHM = 'sha256';")).toEqual([]);
    // Unknown or ambiguous values keep the old behaviour: no finding.
    expect(hash("let ALGORITHM = 'md5';", "ALGORITHM = pick();")).toEqual([]);
    expect(hash("const ALGORITHM = process.env.ALGO;")).toEqual([]);
    expect(
      rulesIn(
        "import crypto from 'crypto'; const ALGORITHM = 'md5'; function f(password, ALGORITHM) { return crypto.createHash(ALGORITHM).update(password); }",
      ),
    ).toEqual([]);
    const cipher = (name: string) =>
      rulesIn(
        `import crypto from 'crypto'; const CIPHER = '${name}'; crypto.createCipheriv(CIPHER, key, iv);`,
      );
    expect(cipher("aes-128-ecb")).toEqual(["PG-CRYPTO-003"]);
    expect(cipher("des-ede3-cbc")).toEqual(["PG-CRYPTO-003"]);
    expect(cipher("aes-256-gcm")).toEqual([]);
    const [weak] = findingsIn(
      "import crypto from 'crypto'; const CIPHER = 'rc4'; crypto.createCipheriv(CIPHER, key, iv);",
    );
    expect(weak?.evidence).toContain("held in constant CIPHER");
  });

  it("flags a secret held in a constant and passed to a signing call", () => {
    const secretOf = (decl: string, call: string) =>
      findingsIn(`import jwt from 'jsonwebtoken'; import crypto from 'crypto'; ${decl} ${call}`);
    const direct = secretOf("const SECRET = 'my-jwt-signing-value';", "jwt.sign(p, SECRET);");
    expect(direct.map((f) => f.ruleId)).toEqual(["PG-CRYPTO-002"]);
    expect(direct[0]).toMatchObject({ severity: "high", confidence: "high" });
    expect(JSON.stringify(direct)).not.toContain("my-jwt-signing-value");
    expect(direct[0]?.evidence).toContain("held in constant SECRET");
    expect(
      secretOf("const KEY = 'webhook-signing-key';", "crypto.createHmac('sha256', KEY);").map(
        (f) => f.ruleId,
      ),
    ).toEqual(["PG-CRYPTO-002"]);
    const fallback = secretOf(
      "const SECRET = process.env.S || 'dev-fallback';",
      "jwt.sign(p, SECRET);",
    );
    expect(fallback[0]).toMatchObject({ severity: "medium", confidence: "medium" });
    // Not fixed at the sink: environment, parameter that shadows the constant, reassigned.
    expect(secretOf("const SECRET = process.env.S;", "jwt.sign(p, SECRET);")).toEqual([]);
    expect(
      secretOf("const secret = 'x'; function f(p, secret) {", "return jwt.sign(p, secret); }"),
    ).toEqual([]);
    expect(secretOf("let secret = 'x'; secret = load();", "jwt.sign(p, secret);")).toEqual([]);
  });

  it("follows a constant key into jose SignJWT and jwtVerify", () => {
    const jose = (body: string) => rulesIn(`import { SignJWT, jwtVerify } from 'jose'; ${body}`);
    expect(
      jose(
        "const k = new TextEncoder().encode('hardcoded-secret-value'); new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).sign(k);",
      ),
    ).toEqual(["PG-CRYPTO-002"]);
    expect(
      jose("const k = new TextEncoder().encode('hardcoded-secret-value'); jwtVerify(token, k);"),
    ).toEqual(["PG-CRYPTO-002"]);
    expect(
      jose(
        "const k = new TextEncoder().encode(process.env.S); new SignJWT({}).setProtectedHeader({}).sign(k);",
      ),
    ).toEqual([]);
  });

  it("flags broken ciphers", () => {
    expect(
      rulesIn(
        "import crypto from 'crypto'; crypto.createCipheriv('des-ede3', key, iv); crypto.createCipher('aes192', key);",
      ),
    ).toEqual(["PG-CRYPTO-003", "PG-CRYPTO-003"]);
    expect(
      rulesIn("import crypto from 'crypto'; crypto.createCipheriv('aes-256-gcm', key, iv);"),
    ).toEqual([]);
  });
});

describe("PG-AUTH-001 plaintext password storage", () => {
  it("flags storing request password without hashing", () => {
    expect(
      rulesIn(
        "async function signup(req) { await User.create({ email: req.body.email, password: req.body.password }); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        "async function signup(email, password) { await prisma.user.create({ data: { email, password } }); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
  });

  it("does not flag when the password is hashed in the same function", () => {
    expect(
      rulesIn(
        "import bcrypt from 'bcrypt'; async function signup(req) { const password = await bcrypt.hash(req.body.password, 12); await User.create({ password }); }",
      ),
    ).toEqual([]);
    expect(rulesIn("async function f(req) { await User.create({ password: hashed }); }")).toEqual(
      [],
    );
  });
});

describe("PG-AUTH-001 instance and raw SQL storage", () => {
  it("flags assign-then-save and new Model({password}).save()", () => {
    expect(
      rulesIn(
        "async function f(req) { const u = new User(); u.password = req.body.password; await u.save(); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        "async function f(req) { const u = new User({ password: req.body.password }); await u.save(); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn("async function f(req) { await new User({ password: req.body.password }).save(); }"),
    ).toEqual(["PG-AUTH-001"]);
  });

  it("does not flag hashed, unsaved or non-request assignments", () => {
    expect(
      rulesIn(
        "async function f(req) { const u = new User(); u.password = await argon2.hash(req.body.password); await u.save(); }",
      ),
    ).toEqual([]);
    expect(rulesIn("function f(req) { const v = {}; v.password = req.body.password; }")).toEqual(
      [],
    );
    expect(
      rulesIn("async function f() { const u = new User(); u.password = 'x'; await u.save(); }"),
    ).toEqual([]);
    expect(
      rulesIn("function f(req) { const u = new User({ password: req.body.password }); }"),
    ).toEqual([]);
  });

  it("flags a raw SQL INSERT/UPDATE bound to the password column only", () => {
    expect(
      rulesIn(
        'async function f(req) { await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [req.body.email, req.body.password]); }',
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        'async function f(req) { await db.run("INSERT INTO users (email, password) VALUES (?, ?)", [req.body.email, req.body.password]); }',
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        'async function f(req) { await db.query("UPDATE users SET password = $1 WHERE id = $2", [req.body.password, 1]); }',
      ),
    ).toEqual(["PG-AUTH-001"]);
    // The request value sits in the email column, not the password column.
    expect(
      rulesIn(
        'async function f(req) { await pool.query("INSERT INTO users (password, email) VALUES ($1, $2)", [gen, req.body.email]); }',
      ),
    ).toEqual([]);
    // Hashing inside the SQL text.
    expect(
      rulesIn(
        "async function f(req) { await pool.query(\"INSERT INTO users (email, password) VALUES ($1, crypt($2, gen_salt('bf')))\", [req.body.email, req.body.password]); }",
      ),
    ).toEqual([]);
  });
});

describe("PG-AUTH-001 plain-value and SQL parsing details", () => {
  const sql = (statement: string, params: string, before = "") =>
    findingsIn(
      `${before} async function f(req) { await pool.query(${statement}, ${params}); }`,
    ).filter((finding) => finding.ruleId === "PG-AUTH-001");

  it("never treats a value returned from a call as a plain password", () => {
    const insert = '"INSERT INTO users (email, password) VALUES ($1, $2)"';
    expect(sql(insert, "[req.body.email, hashSecret(req.body.password)]")).toEqual([]);
    expect(sql(insert, "[req.body.email, makeDigest(req.body.password)]")).toEqual([]);
    expect(sql(insert, "[req.body.email, req.body.password]")).toHaveLength(1);
    expect(
      sql(insert, "[req.body.email, stored]", "const stored = secure(req.body.password);"),
    ).toEqual([]);
    expect(sql(insert, "[req.body.email, pw]", "const pw = req.body.password;")).toHaveLength(1);
    expect(
      rulesIn(
        "async function f(req) { const u = new User(); u.password = secure(req.body.password); await u.save(); }",
      ),
    ).toEqual([]);
    expect(
      rulesIn(
        "async function f(req) { await User.create({ password: hashSecret(req.body.password) }); }",
      ),
    ).toEqual([]);
  });

  it("counts placeholders outside string literals and comments only", () => {
    expect(
      sql(
        `"INSERT INTO users (note, password, email) VALUES ('ok?', ?, ?)"`,
        "[gen, req.body.email]",
      ),
    ).toEqual([]);
    expect(
      sql(
        `"INSERT INTO users (password, email) VALUES (?, ?) -- why? because"`,
        "[req.body.password, e]",
      ),
    ).toHaveLength(1);
    expect(
      sql(`"INSERT INTO users (note, password) VALUES ('a,b', $1)"`, "[req.body.password]"),
    ).toHaveLength(1);
  });

  it("parses VALUES with function calls, SQL held in a const, pass columns and named params", () => {
    expect(
      sql(
        '"INSERT INTO users (email, created_at, password) VALUES ($1, NOW(), $2)"',
        "[req.body.email, req.body.password]",
      ),
    ).toHaveLength(1);
    expect(
      sql(
        "Q",
        "[req.body.email, req.body.password]",
        'const Q = "INSERT INTO u (e, password) VALUES ($1, $2)";',
      ),
    ).toHaveLength(1);
    expect(
      sql('"UPDATE users SET pass = $1 WHERE id = $2"', "[req.body.password, 1]"),
    ).toHaveLength(1);
    expect(
      sql(
        '"INSERT INTO users (email, password) VALUES (@email, @password)"',
        "{ email: e, password: req.body.password }",
      ),
    ).toHaveLength(1);
    expect(
      sql(
        '"INSERT INTO users (email, password) VALUES (:email, :password)"',
        "{ email: req.body.email, password: p }",
      ),
    ).toEqual([]);
  });

  it("falls back to a low-confidence finding when columns and values do not line up", () => {
    // Exact mapping: medium. Mismatched counts: only a bound password read counts, at low confidence.
    const mapped = sql(
      '"INSERT INTO users (email, password) VALUES ($1, $2)"',
      "[e, req.body.password]",
    );
    expect(mapped[0]?.confidence).toBe("medium");
    const mismatched = sql(
      '"INSERT INTO users (email, password) VALUES ($1, $2, $3)"',
      "[req.body.email, req.body.password, x]",
    );
    expect(mismatched).toHaveLength(1);
    expect(mismatched[0]?.confidence).toBe("low");
    // A request value that is not a password read does not trigger the fallback.
    expect(
      sql('"INSERT INTO users (email, password) VALUES ($1, $2, $3)"', "[req.body.email, g, x]"),
    ).toEqual([]);
  });

  it("skips SQL that hashes, and unsaved lowercase constructors", () => {
    expect(
      sql(
        '"INSERT INTO users (email, password) VALUES ($1, $2) /* hashed by trigger: sha256 */"',
        "[req.body.email, req.body.password]",
      ),
    ).toEqual([]);
    expect(
      rulesIn(
        "async function f(req) { const u = new user({ password: req.body.password }); await u.save(); }",
      ),
    ).toEqual([]);
  });
});

describe("PG-AUTH-001 request-derived identifiers", () => {
  const create = (body: string) =>
    rulesIn(`async function f(req) { ${body} await User.create({ password: v }); }`);

  it("treats destructured, renamed and single-assignment request values as plain", () => {
    expect(create("const { password: v } = req.body;")).toEqual(["PG-AUTH-001"]);
    expect(create("const { newPass: v } = req.body;")).toEqual(["PG-AUTH-001"]);
    expect(create("let v = req.body.pw;")).toEqual(["PG-AUTH-001"]);
    expect(create("const v = req.body.pw;")).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        "async function f(req) { const { pw } = req.body; await knex('u').update({ password: pw }); }",
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        "app.post('/r', async ({ body }) => { const { pw } = body; await User.create({ password: pw }); });",
      ),
    ).toEqual(["PG-AUTH-001"]);
    expect(
      rulesIn(
        "app.post('/r', async ({ body }) => { const v = body.pw; await User.create({ password: v }); });",
      ),
    ).toEqual(["PG-AUTH-001"]);
  });

  it("does not treat reassigned lets, call results or unrelated destructuring as plain", () => {
    expect(create("let v = req.body.pw; v = secure(v);")).toEqual([]);
    expect(create("const v = secure(req.body.pw);")).toEqual([]);
    expect(create("const { pw: v } = await lookup(req);")).toEqual([]);
    expect(create("const { v } = config;")).toEqual([]);
    // A property of a call result is not a request value either.
    expect(
      rulesIn("async function f() { await Backup.create({ password: getUser().password }); }"),
    ).toEqual([]);
  });
});

describe("PG-COOKIE-001 option resolution and name filter", () => {
  it("matches cookie names by whole word", () => {
    for (const name of [
      "session",
      "sessionId",
      "connect.sid",
      "__Host-sid",
      "__Secure-auth_token",
      "jwt",
      "refresh_token",
      "remember_me",
      "SESSION_COOKIE",
    ])
      expect(rulesIn(`res.cookie('${name}', v);`), name).toEqual(["PG-COOKIE-001"]);
    for (const name of [
      "access_log_consent",
      "accessibility",
      "sidebar_state",
      "theme",
      "residence",
      "authority",
    ])
      expect(rulesIn(`res.cookie('${name}', v);`), name).toEqual([]);
    expect(findingsIn("res.cookie('uid', v);")[0]).toMatchObject({
      confidence: "low",
      severity: "low",
    });
    expect(findingsIn("res.cookie('sid', v);")[0]).toMatchObject({ confidence: "medium" });
  });

  it("marks a session-like cookie as a cookie session for CSRF", () => {
    expect(analyzeJsSource("res.cookie('session', v, {});", "s.js").facts.usesCookieSession).toBe(
      true,
    );
    expect(analyzeJsSource("res.cookie('theme', v, {});", "s.js").facts.usesCookieSession).toBe(
      false,
    );
  });

  it("resolves sameSite and cookie options held in consts for express-session", () => {
    const base = "import session from 'express-session';";
    const strict = analyzeJsSource(
      `${base} const SS = 'strict'; app.use(session({ secret: s, cookie: { httpOnly: true, secure: true, sameSite: SS } }));`,
      "s.ts",
    );
    expect(strict.findings).toEqual([]);
    expect(strict.facts.strictSession).toBe(true);
    const viaConst = analyzeJsSource(
      `${base} const C = { httpOnly: true, secure: true, sameSite: 'lax' }; app.use(session({ secret: s, cookie: C }));`,
      "s.ts",
    );
    expect(viaConst.findings).toEqual([]);
    const imported = analyzeJsSource(
      `${base} app.use(session({ secret: s, cookie: imported }));`,
      "s.ts",
    );
    expect(imported.findings[0]?.evidence).toContain("options not resolvable");
  });

  it("resolves options held in a same-file const", () => {
    expect(
      rulesIn("const o = { httpOnly: true }; function f(res) { res.cookie('sid', t, o); }"),
    ).toEqual(["PG-COOKIE-001"]);
    expect(
      rulesIn(
        "const o = { httpOnly: true, secure: true, sameSite: 'lax' }; function f(res) { res.cookie('sid', t, o); }",
      ),
    ).toEqual([]);
    // A reassignable binding or an imported object cannot be resolved: reported unverified, low.
    for (const code of [
      "let o = {}; o = other; function f(res) { res.cookie('sid', t, o); }",
      "function f(res) { res.cookie('sid', t, imported); }",
    ]) {
      const [finding] = findingsIn(code);
      expect(finding).toMatchObject({ ruleId: "PG-COOKIE-001", confidence: "low" });
      expect(finding?.evidence).toContain("options not resolvable");
    }
    // ...but only for session-like cookies.
    expect(rulesIn("function f(res) { res.cookie('theme', 'x', imported); }")).toEqual([]);
  });

  it("resolves object spreads of local consts and skips unknown spreads", () => {
    expect(
      rulesIn(
        "const S = { httpOnly: true, secure: true, sameSite: 'lax' }; function f(res) { res.cookie('sid', t, { ...S, maxAge: 1 }); }",
      ),
    ).toEqual([]);
    expect(
      rulesIn(
        "const S = { httpOnly: true }; function f(res) { res.cookie('sid', t, { ...S, secure: true }); }",
      ),
    ).toEqual(["PG-COOKIE-001"]);
    expect(
      findingsIn("function f(res) { res.cookie('sid', t, { ...other }); }")[0]?.evidence,
    ).toContain("options not resolvable");
  });

  it("counts sameSite: false as not set, and matches session values by word", () => {
    expect(
      rulesIn("res.cookie('sid', t, { httpOnly: true, secure: true, sameSite: false });"),
    ).toEqual(["PG-COOKIE-001"]);
    expect(rulesIn("res.cookie('app', jwtValue);")).toEqual(["PG-COOKIE-001"]);
    expect(rulesIn("res.cookie('app', accessToken);")).toEqual(["PG-COOKIE-001"]);
    expect(rulesIn("res.cookie('editor_mode', tokenizerMode);")).toEqual([]);
    expect(rulesIn("res.cookie('refresh', r);")).toEqual(["PG-COOKIE-001"]);
  });

  it("recognises Koa, NextResponse and Hono cookie APIs", () => {
    // Koa defaults httpOnly on; secure and sameSite are still missing.
    const [koa] = findingsIn("ctx.cookies.set('session', v, { maxAge: 1 });");
    expect(koa?.evidence).toContain("without secure, sameSite");
    expect(
      rulesIn("ctx.cookies.set('session', v, { httpOnly: false, secure: true, sameSite: 'lax' });"),
    ).toEqual(["PG-COOKIE-001"]);
    expect(
      rulesIn(
        "import { NextResponse } from 'next/server'; const res = NextResponse.json({}); res.cookies.set('session', 'x');",
      ),
    ).toEqual(["PG-COOKIE-001"]);
    expect(rulesIn("res.cookies.set('session', 'x');")).toEqual([]);
    expect(
      rulesIn("import { setCookie } from 'hono/cookie'; setCookie(c, 'session', 'x');"),
    ).toEqual(["PG-COOKIE-001"]);
    expect(
      rulesIn(
        "import { setCookie } from 'hono/cookie'; setCookie(c, 'session', 'x', { httpOnly: true, secure: true, sameSite: 'Lax' });",
      ),
    ).toEqual([]);
  });

  it("only judges session or auth looking cookies", () => {
    expect(rulesIn("res.cookie('theme', 'dark');")).toEqual([]);
    expect(rulesIn("res.cookie('lang', 'ko', { path: '/' });")).toEqual([]);
    expect(findingsIn("res.cookie('app', accessToken);")[0]).toMatchObject({
      ruleId: "PG-COOKIE-001",
      confidence: "low",
    });
    expect(findingsIn("res.cookie('connect.sid', v);")[0]).toMatchObject({ severity: "medium" });
  });

  it("recognises the Next.js cookies().set() API", () => {
    const next = "import { cookies } from 'next/headers';";
    expect(
      rulesIn(
        `${next} async function f() { (await cookies()).set('auth_token', 'x', { path: '/' }); }`,
      ),
    ).toEqual(["PG-COOKIE-001"]);
    expect(
      rulesIn(
        `${next} async function f() { const s = await cookies(); s.set({ name: 'session', value: 'x' }); }`,
      ),
    ).toEqual(["PG-COOKIE-001"]);
    expect(
      rulesIn(
        `${next} async function f() { (await cookies()).set('auth_token', 'x', { httpOnly: true, secure: true, sameSite: 'lax' }); }`,
      ),
    ).toEqual([]);
    expect(
      rulesIn(`${next} async function f() { (await cookies()).set('theme', 'dark'); }`),
    ).toEqual([]);
    // `cookies` from somewhere else is not the Next.js API.
    expect(rulesIn("import { cookies } from './jar'; cookies().set('session', 'x');")).toEqual([]);
  });
});

describe("CSRF facts", () => {
  it("separates POST from preflighted methods and detects credentialed permissive CORS", () => {
    const base = "import express from 'express'; import cors from 'cors'; const app = express();";
    const factsFor = (setup: string) =>
      analyzeJsSource(`${base} ${setup} app.put('/a', h); app.post('/b', h);`, "s.ts").facts;
    const exposure = (setup: string) => factsFor(setup).preflightExposure;
    // Provably restrictive: no CORS, no credentials, a fixed origin or origin list.
    expect(exposure("")).toBeNull();
    expect(exposure("app.use(cors());")).toBeNull();
    expect(exposure("app.use(cors({ origin: true }));")).toBeNull();
    expect(
      exposure("app.use(cors({ origin: ['https://a.example'], credentials: true }));"),
    ).toBeNull();
    expect(
      exposure("app.use(cors({ origin: 'https://a.example', credentials: true }));"),
    ).toBeNull();
    expect(
      exposure("const O = ['https://a.example']; app.use(cors({ origin: O, credentials: true }));"),
    ).toBeNull();
    // Permissive: reflected, pattern or function origin with credentials.
    expect(exposure("app.use(cors({ origin: true, credentials: true }));")).toBe("permissive");
    expect(exposure("app.use(cors({ origin: /example/, credentials: true }));")).toBe("permissive");
    expect(
      exposure("app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));"),
    ).toBe("permissive");
    expect(
      exposure(
        "app.use(cors({ origin: function (o, cb) { cb(null, true); }, credentials: true }));",
      ),
    ).toBe("permissive");
    // Unknown: unresolvable options, identifier origin, mixed list, hand-set header, method-override.
    expect(exposure("app.use(cors(imported));")).toBe("unknown");
    expect(exposure("app.use(cors({ origin: checkOrigin, credentials: true }));")).toBe("unknown");
    expect(exposure("app.use(cors({ origin: ['https://a', other], credentials: true }));")).toBe(
      "unknown",
    );
    expect(exposure("app.use(cors({ origin: true, credentials: flag }));")).toBe("unknown");
    expect(
      exposure("app.use((q, r) => r.header('Access-Control-Allow-Credentials', 'true'));"),
    ).toBe("unknown");
    expect(
      exposure("app.use((q, r) => r.header('Access-Control-Allow-Credentials', 'false'));"),
    ).toBeNull();
    expect(
      analyzeJsSource("import mo from 'method-override'; app.use(mo());", "s.ts").facts
        .preflightExposure,
    ).toBe("unknown");
    expect(factsFor("").stateChangingRoutes).toHaveLength(1);
    expect(factsFor("").preflightRoutes).toHaveLength(1);
  });

  it("detects @fastify/cors registered with credentials, and strict sessions", () => {
    const { facts } = analyzeJsSource(
      "import cors from '@fastify/cors'; app.register(cors, { origin: true, credentials: true });",
      "s.ts",
    );
    expect(facts.preflightExposure).toBe("permissive");
    const strict = analyzeJsSource(
      "import session from 'express-session'; app.use(session({ secret: s, cookie: { sameSite: 'strict' } }));",
      "s.ts",
    ).facts;
    expect(strict).toMatchObject({ strictSession: true, usesCookieSession: false });
    expect(
      analyzeJsSource(
        "import session from 'express-session'; app.use(session({ secret: s, cookie: { sameSite: 'lax' } }));",
        "s.ts",
      ).facts,
    ).toMatchObject({ strictSession: false, usesCookieSession: true });
  });
});

describe("PG-COOKIE-001", () => {
  it("flags session cookies without flags", () => {
    const [finding] = findingsIn("res.cookie('session', token);");
    expect(finding).toMatchObject({ ruleId: "PG-COOKIE-001", severity: "medium" });
    expect(finding?.evidence).toContain("httpOnly");
  });

  it("flags express-session without secure", () => {
    expect(
      rulesIn(
        "import session from 'express-session'; app.use(session({ secret: process.env.S, cookie: { httpOnly: true, sameSite: 'lax' } }));",
      ),
    ).toEqual(["PG-COOKIE-001"]);
  });

  it("does not flag fully configured cookies", () => {
    expect(
      rulesIn(
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });",
      ),
    ).toEqual([]);
    expect(
      rulesIn(
        "import session from 'express-session'; app.use(session({ secret: process.env.S, cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }));",
      ),
    ).toEqual([]);
  });
});

describe("facts and robustness", () => {
  it("collects routes, imports and cookie usage for project heuristics", () => {
    const { facts } = analyzeJsSource(
      "import express from 'express'; const app = express(); app.post('/login', h); app.delete('/items/:id', h); res.cookie('sid', v, opts);",
      "src/server.js",
    );
    expect(facts.imports).toContain("express");
    expect(facts.authRoutes).toEqual([{ line: 1, routePath: "/login" }]);
    expect(facts.stateChangingRoutes).toHaveLength(1);
    expect(facts.preflightRoutes).toHaveLength(1);
    // A session-like cookie set by hand counts as a cookie session; other cookies do not.
    expect(facts.usesCookieSession).toBe(true);
  });

  it("reports syntax errors without throwing", () => {
    const analysis = analyzeJsSource("function (", "src/broken.ts");
    expect(analysis.hasParseErrors).toBe(true);
  });

  it("applies the line offset for embedded scripts", () => {
    const { findings } = analyzeJsSource("\n\nel.innerHTML = html;", "c.vue", { lineOffset: 10 });
    expect(findings[0]?.line).toBe(13);
  });
});

describe("per-function facts stay linear (#104)", () => {
  it("analyzes many crypto and persistence call sites in one large function quickly", () => {
    const body = Array.from(
      { length: 6000 },
      (_, index) =>
        `  crypto.createHash("md5").update(x${index}); await User.create({ password: req.body.p${index} });`,
    ).join("\n");
    const code = `import crypto from "crypto";\nasync function big(req) {\n${body}\n}\n`;
    expect(code.length).toBeGreaterThan(400_000);
    expect(bestTimeOf(3, () => analyzeJsSource(code, "big.js"))).toBeLessThan(5000 * SLOW);
  }, 60_000);

  it("still detects MD5 of passwords via update() in the same function", () => {
    const rules = analyzeJsSource(
      "import crypto from 'crypto'; function f(password) { const h = crypto.createHash('md5'); h.update(password); }",
      "a.js",
    ).findings.map((f) => f.ruleId);
    expect(rules).toEqual(["PG-CRYPTO-001"]);
  });
});

describe("SQL through local db modules, identifier args and multi-line SQL (#84)", () => {
  it("flags a query string assigned to a variable and run through a local db module", () => {
    expect(
      rulesIn(
        "import db from './db';\nconst q = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(q);",
      ),
    ).toEqual(["PG-SQL-001"]);
  });

  it("flags multi-line SQL templates", () => {
    expect(
      rulesIn(
        "import db from './db';\ndb.query(`\n  SELECT *\n  FROM users\n  WHERE id = ${id}\n`);",
      ),
    ).toEqual(["PG-SQL-001"]);
  });

  it("still ignores non-SQL query() calls on unknown receivers", () => {
    expect(rulesIn("search.query(`${term} near ${place}`);")).toEqual([]);
  });
});

describe("request input passed straight to raw SQL sinks (#85)", () => {
  it.each([
    ["import { Pool } from 'pg'; pool.query(req.body.sql);"],
    ["import db from './db'; db.query(req.body.sql);"],
    ["await prisma.$queryRawUnsafe(req.body.q);"],
    ["const q = req.body.q; await prisma.$executeRawUnsafe(q);"],
  ])("flags %s", (code) => {
    expect(rulesIn(code).some((id) => id.startsWith("PG-SQL"))).toBe(true);
  });
});

describe("shells via spawn/execFile and promisified exec (#86)", () => {
  it.each([
    ["import { spawn } from 'child_process'; spawn('sh', ['-c', req.query.cmd]);"],
    ["import { execFile } from 'node:child_process'; execFile('bash', ['-c', 'ls ' + dir]);"],
    [
      "import util from 'util'; import { exec } from 'child_process'; const run = util.promisify(exec); run(req.body.cmd);",
    ],
    [
      "import { promisify } from 'util'; import cp from 'child_process'; const run = promisify(cp.exec); await run(`tar ${f}`);",
    ],
  ])("flags %s", (code) => {
    expect(rulesIn(code)).toContain("PG-CMD-001");
  });

  it("does not flag a constant script", () => {
    expect(
      rulesIn("import { spawn } from 'child_process'; spawn('sh', ['-c', 'echo ok']);"),
    ).toEqual([]);
  });
});

describe("linear cost and caps (#87)", () => {
  it("analyzes a large JS file quickly", () => {
    const build = (count: number) =>
      Array.from(
        { length: count },
        (_, index) =>
          `function f${index}(req) { const password = req.body.p${index}; el.innerHTML = x${index}; return check(password); }`,
      ).join("\n");
    const code = build(8000);
    expect(code.length).toBeGreaterThan(500_000);
    const quarter = build(2000);
    let analysis = analyzeJsSource(code, "big.js");
    const large = bestTimeOf(3, () => {
      analysis = analyzeJsSource(code, "big.js");
    });
    const small = bestTimeOf(3, () => analyzeJsSource(quarter, "big.js"));
    expect(large).toBeLessThan(5000 * SLOW);
    // Four times the input: linear is about 4x, quadratic about 16x.
    expect(large / Math.max(small, 1)).toBeLessThan(10);
    expect(analysis.cappedRules).toContain("PG-XSS-001");
  }, 60_000);

  it("resolves sanitized variables in linear time when many scopes share a name (#109)", () => {
    const build = (count: number) =>
      Array.from(
        { length: count },
        (_, index) =>
          `function f${index}() { const h = DOMPurify.sanitize(a${index}); el.innerHTML = h; }`,
      ).join("\n");
    const time = (code: string) => {
      expect(analyzeJsSource(code, "big.js").findings).toEqual([]);
      return bestTimeOf(3, () => analyzeJsSource(code, "big.js"));
    };
    time(build(500)); // warm up
    const small = time(build(4000));
    const large = time(build(32000));
    // Quadratic resolution took ~20 s at 8,000 scopes. Linear time grows roughly 8x for 8x the
    // input (64x if quadratic). Only the ratio is checked, with a generous limit and the best of
    // 3 runs per size: CI runners are much slower than local machines, so absolute bounds are
    // flaky.
    expect(large / Math.max(small, 1)).toBeLessThan(40);
  }, 120_000);
});

describe("precision (#88)", () => {
  it("treats new URLSearchParams(location.search) as browser input", () => {
    const [finding] = findingsIn(
      "const p = new URLSearchParams(location.search); el.innerHTML = p.get('m');",
      "a.ts",
    );
    expect(finding).toMatchObject({ ruleId: "PG-XSS-001", severity: "high" });
  });

  it("does not treat constant += concatenation as dynamic SQL", () => {
    expect(
      rulesIn(
        "import { Pool } from 'pg'; let sql = 'SELECT * FROM t'; sql += ' WHERE a = $1'; pool.query(sql, [a]);",
      ),
    ).toEqual([]);
  });
});

describe("injection precision and recall (#242)", () => {
  // Full suppression is only for values fixed by the expression itself. Anything inferred (guards,
  // allowlist tables, aliases, local constants) stays a finding at low confidence.
  const strongRules = (code: string) =>
    findingsIn(code)
      .filter((finding) => finding.confidence !== "low")
      .map((finding) => finding.ruleId);
  const allRules = (code: string) => findingsIn(code).map((finding) => finding.ruleId);
  /** No finding at all: the value is fixed by the expression itself. */
  const expectSuppressed = (code: string) => expect(allRules(code)).toEqual([]);
  /** Kept, but only at low confidence (recognised, not proven). */
  const expectDemoted = (code: string, rule: string) => {
    expect(allRules(code)).toEqual([rule]);
    expect(strongRules(code)).toEqual([]);
    const [finding] = findingsIn(code);
    expect(finding?.severity).not.toBe("high");
    expect(finding?.severity).not.toBe("critical");
  };
  /** Kept without being demoted: no "inferred" or "recognised guard" excuse was applied. */
  const expectNotDemoted = (code: string, rule: string) => {
    const mine = findingsIn(code).filter((finding) => finding.ruleId === rule);
    expect(mine.length).toBeGreaterThan(0);
    expect(
      mine.some((finding) => !/inferred to be fixed|guard recognised/.test(finding.evidence)),
    ).toBe(true);
  };
  /** Reported at medium or high confidence. */
  const expectFires = (code: string, rule: string) => expect(strongRules(code)).toContain(rule);

  const SQL_HEAD = "import { Pool } from 'pg'; const pool = new Pool();";

  it("fully suppresses only values fixed by the expression itself", () => {
    expectSuppressed(
      `${SQL_HEAD} const T = 'logs';
       export const f = (req) => pool.query(\`SELECT * FROM \${T} LIMIT \${Number.parseInt(req.query.n, 10) || 5} OFFSET \${+req.query.o}\`);`,
    );
    expectSuppressed(`${SQL_HEAD} export const f = () => pool.query(\`SELECT * FROM t\`);`);
  });

  it("does not suppress numeric coercion when a built-in is shadowed or monkeypatched", () => {
    const query = (expression: string, prelude = "") =>
      `${SQL_HEAD} ${prelude} export const f = (req) => pool.query(\`SELECT * FROM t LIMIT \${${expression}}\`);`;
    expectSuppressed(query("Number(req.query.n)"));
    expectSuppressed(query("parseInt(req.query.n, 10)"));
    expectSuppressed(query("Math.min(Number(req.query.n), 5)"));
    for (const [expression, prelude] of [
      ["Number(req.query.n)", "function Number(x) { return x; }"],
      ["Number(req.query.n)", "const Number = (x) => x;"],
      ["parseInt(req.query.n, 10)", "const parseInt = (x) => x;"],
      ["parseInt(req.query.n, 10)", "parseInt = (x) => x;"],
      ["Number.parseInt(req.query.n, 10)", "Number.parseInt = (x) => x;"],
      ["Math.max(0, req.query.n)", "Math.max = (a, b) => b;"],
    ] as const)
      expect(allRules(query(expression, prelude)), `${prelude} ${expression}`).toContain(
        "PG-SQL-001",
      );
  });

  it("demotes, and does not suppress, a command taken from a lookup table", () => {
    const head = "import { exec } from 'child_process'; const TOOLS = new Map([['a', 'ls']]);";
    expectDemoted(
      `${head} export const f = (req) => exec(\`\${TOOLS.get(req.query.k)} -l\`);`,
      "PG-CMD-001",
    );
    expectSuppressed(
      "import { exec } from 'child_process'; import { quote } from 'shell-quote'; export const f = (req) => exec('ls ' + quote([req.query.d]));",
    );
  });

  it("demotes values that are only inferred to be fixed", () => {
    // allowlist Map / object / ternary
    expectDemoted(
      `${SQL_HEAD} const M = new Map([['a','x ASC']]);
       export const f = (req) => pool.query(\`SELECT * FROM t ORDER BY \${M.get(req.query.s) ?? 'id'}\`);`,
      "PG-SQL-001",
    );
    // a constant that is local to the function, and one built from another constant
    expectDemoted(
      `${SQL_HEAD} export const f = (req) => { const limit = Number(req.query.n) || 5;
       return pool.query(\`SELECT * FROM t LIMIT \${limit}\`); };`,
      "PG-SQL-001",
    );
    expectDemoted(
      `${SQL_HEAD} const S = 'a'; const U = \`\${S}.users\`;
       export const f = () => pool.query(\`SELECT * FROM \${U}\`);`,
      "PG-SQL-001",
    );
  });

  it("still flags a request value next to an allowlisted one", () => {
    expectFires(
      `${SQL_HEAD} const M = new Map([['a','x']]);
       export const f = (req) => pool.query('SELECT * FROM t WHERE n = ' + req.query.n + ' ORDER BY ' + M.get(req.query.s));`,
      "PG-SQL-001",
    );
  });

  it("does not trust a constant that another binding of the same name shadows", () => {
    const table = "const table = 'users';";
    const query = "pool.query('SELECT * FROM ' + table)";
    for (const shadow of [
      `export const f = async (table) => ${query};`,
      `export const f = async (req) => { const { table } = req.query; return ${query}; };`,
      `export const f = async (req) => { try { x(); } catch (table) { return ${query}; } };`,
      `export function table(req) { return ${query}; }`,
      `export const f = async (req) => { const table = req.query.t; return ${query}; };`,
    ])
      expectNotDemoted(`${SQL_HEAD} ${table} ${shadow}`, "PG-SQL-001");
    expectSuppressed(`${SQL_HEAD} ${table} export const f = () => ${query};`);
  });

  it("sees every write form that changes a constant", () => {
    const head = `${SQL_HEAD} const table = 'users';`;
    const query = "pool.query('SELECT * FROM ' + table)";
    for (const write of [
      "table = req.query.t;",
      "for (table of req.body.tables) {}",
      "for (table in req.body.tables) {}",
      "({ table } = req.query);",
      "({ a: table = 'x' } = req.query);",
      "[table] = req.body.tables;",
      "[...table] = req.body.tables;",
    ])
      expectNotDemoted(
        `${head} export const f = (req) => { ${write} return ${query}; };`,
        "PG-SQL-001",
      );
  });

  it("does not trust an allowlist table that is written to or escapes", () => {
    const head = `${SQL_HEAD} const T = { a: 'x' };`;
    const query = "pool.query('SELECT * FROM t ORDER BY ' + T[req.query.k])";
    expectDemoted(`${head} export const f = (req) => ${query};`, "PG-SQL-001");
    for (const body of [
      `T[req.query.k] = req.query.v; return ${query};`,
      `T.a = req.query.v; return ${query};`,
      `Object.assign(T, req.query); return ${query};`,
      `register(T); return ${query};`,
      `delete T.a; return ${query};`,
    ])
      expectNotDemoted(`${head} export const f = (req) => { ${body} };`, "PG-SQL-001");
    const map = (entries: string, extra = "") =>
      `${SQL_HEAD} const M = new Map(${entries}); export const f = (req) => { ${extra} return pool.query('SELECT * FROM t ORDER BY ' + M.get(req.query.k)); };`;
    expectDemoted(map("[['a', 'x']]"), "PG-SQL-001");
    expectNotDemoted(map("[['a', req.query.v]]"), "PG-SQL-001");
    expectNotDemoted(map("[['a', 'x']]", "M.set('b', req.query.v);"), "PG-SQL-001");
  });

  it("does not trust an exported allowlist table", () => {
    const query = "pool.query('SELECT * FROM t ORDER BY ' + T[req.query.k])";
    expectDemoted(
      `${SQL_HEAD} const T = { a: 'x' }; export const f = (req) => ${query};`,
      "PG-SQL-001",
    );
    expectNotDemoted(
      `${SQL_HEAD} export const T = { a: 'x' }; export const f = (req) => ${query};`,
      "PG-SQL-001",
    );
  });

  it("flags Prisma.raw of an unresolved value at low confidence, not a literal", () => {
    const [finding] = findingsIn(
      "import { Prisma } from '@prisma/client'; export const f = (col: string) => Prisma.sql`SELECT * FROM t ORDER BY ${Prisma.raw(col)}`;",
    );
    expect(finding).toMatchObject({ ruleId: "PG-SQL-002", confidence: "low" });
    expectSuppressed(
      "import { Prisma } from '@prisma/client'; export const f = () => Prisma.sql`SELECT * FROM t ORDER BY a ${Prisma.raw('DESC')}`;",
    );
  });

  it("trusts quote() only when it is the shell-quote import", () => {
    const body = "exec('git log ' + quote(req.query.ref));";
    const head = "import { exec } from 'child_process';";
    expectSuppressed(`${head} import { quote } from 'shell-quote'; ${body}`);
    expectFires(`${head} import { quote } from './q'; ${body}`, "PG-CMD-001");
    expectFires(
      `${head} import { quote } from 'shell-quote'; export const f = (req) => { const quote = (a) => a.join(' '); ${body} };`,
      "PG-CMD-001",
    );
    expectSuppressed(
      "import { exec } from 'child_process'; const V = '1'; exec(`npm view x@${V}`);",
    );
  });

  describe("path guard (PG-PATH-001)", () => {
    const code = (guard: string, sink = "res.sendFile(p);", prelude = "") =>
      `import path from 'path'; const ROOT = path.resolve('x'); ${prelude}
       export const f = (req, res) => { const p = path.resolve(ROOT, req.query.f); ${guard} ${sink} };`;
    const exit = "return res.end();";

    it("demotes a recognised early-exit guard with a fixed root and a separator", () => {
      expectDemoted(code(`if (!p.startsWith(ROOT + path.sep)) ${exit}`), "PG-PATH-001");
      expectDemoted(code(`if (!p.startsWith(ROOT + '/')) throw new Error('x');`), "PG-PATH-001");
      expectDemoted(code(`if (!p.startsWith(\`\${ROOT}\${path.sep}\`)) ${exit}`), "PG-PATH-001");
      expectDemoted(
        code("", "if (p.startsWith(ROOT + path.sep)) { res.sendFile(p); }"),
        "PG-PATH-001",
      );
      expect(findingsIn(code(`if (!p.startsWith(ROOT + path.sep)) ${exit}`))[0]?.evidence).toMatch(
        /guard recognised at L\d+/,
      );
    });

    it("keeps full confidence without a real separator or a fixed root", () => {
      for (const guard of [
        `if (!p.startsWith(ROOT)) ${exit}`,
        `if (!p.startsWith(ROOT + 'x')) ${exit}`,
        `if (!p.startsWith(req.query.b + path.sep)) ${exit}`,
        `if (!p.startsWith('/' )) ${exit}`,
        `if (!ROOT.startsWith(ROOT + path.sep)) ${exit}`,
      ])
        expectFires(code(guard), "PG-PATH-001");
    });

    it("keeps full confidence when the checked value is not the resolved one that is opened", () => {
      expectFires(
        `import path from 'path'; const ROOT = path.resolve('x');
         export const f = (req, res) => { const a = path.resolve(ROOT, 'i'); const b = path.resolve(ROOT, req.query.f);
         if (!a.startsWith(ROOT + path.sep)) return res.end(); res.sendFile(b); };`,
        "PG-PATH-001",
      );
      expectFires(
        `import path from 'path'; const ROOT = path.resolve('x');
         export const f = (req, res) => { const p = path.resolve('x') + '/' + req.query.f;
         if (!p.startsWith(ROOT + path.sep)) return res.end(); res.sendFile(p); };`,
        "PG-PATH-001",
      );
      expectFires(
        `import path from 'path'; const ROOT = path.resolve('x');
         export const f = (req, res) => { const p = path.join(ROOT, req.query.f);
         if (!p.startsWith(ROOT + path.sep)) return res.end(); res.sendFile(p); };`,
        "PG-PATH-001",
      );
    });

    it("requires the guard to dominate the file operation", () => {
      const guard = `if (!p.startsWith(ROOT + path.sep))`;
      for (const source of [
        code("", `res.sendFile(p); ${guard} ${exit}`),
        code(`${guard} { console.log('x'); }`),
        code(`${guard} console.log('x');`),
        code(`if (req.query.strict) { ${guard} ${exit} }`),
        code(`for (const x of [1]) { ${guard} ${exit} }`),
        code(`try { ${guard} throw new Error('x'); } catch (e) { console.warn(e); }`),
        code(`if (req.query.a) {} else { ${guard} ${exit} }`),
        code("", "if (p.startsWith(ROOT + path.sep)) {} else { res.sendFile(p); }"),
        `import path from 'path'; const ROOT = path.resolve('x');
         function check(p) { if (!p.startsWith(ROOT + path.sep)) return false; return true; }
         export const f = (req, res) => { const p = path.resolve(ROOT, req.query.f); check(p); res.sendFile(p); };`,
      ])
        expectFires(source, "PG-PATH-001");
    });

    it("does not trust a guard when the value changes after it", () => {
      for (const change of [
        "p = path.resolve(ROOT, req.query.b);",
        "for (p of req.body.paths) {}",
        "[p] = req.body.paths;",
        "({ p } = req.body);",
        "p += req.query.b;",
      ])
        expectFires(
          `import path from 'path'; const ROOT = path.resolve('x');
           export const f = (req, res) => { let p = path.resolve(ROOT, req.query.a);
           if (!p.startsWith(ROOT + path.sep)) return res.end(); ${change} res.sendFile(p); };`,
          "PG-PATH-001",
        );
    });

    it("trusts only the real path/fs normalizers, not a local resolve", () => {
      const body = `const full = resolve(ROOT, req.query.name);
        if (!full.startsWith(ROOT + path.sep)) return res.end(); fs.readFileSync(full);`;
      const head = "import fs from 'fs'; import path from 'path'; const ROOT = '/srv';";
      expectFires(
        `${head} const resolve = (b, n) => b + '/' + n; export const f = (req, res) => { ${body} };`,
        "PG-PATH-001",
      );
      expectDemoted(
        `${head} import { resolve } from 'path'; export const f = (req, res) => { ${body} };`,
        "PG-PATH-001",
      );
      expectFires(
        `${head} import { resolve } from './mine'; export const f = (req, res) => { ${body} };`,
        "PG-PATH-001",
      );
      expectFires(
        `${head} import { resolve } from 'path'; export const f = (req, res) => { const resolve = (b, n) => b + n; ${body} };`,
        "PG-PATH-001",
      );
      // an awaited realpath is a normalizer too
      expectDemoted(
        `import { realpath, readFile } from 'node:fs/promises'; import path from 'path'; const ROOT = '/srv';
         export const f = async (req) => { const full = await realpath(path.join(ROOT, req.query.n));
         if (!full.startsWith(ROOT + path.sep)) throw new Error('x'); return readFile(full); };`,
        "PG-PATH-001",
      );
    });
  });

  describe("URL guard (PG-SSRF-001)", () => {
    const code = (guard: string, sink = "fetch(u)", prelude = "const u = new URL(req.query.u);") =>
      `export const f = async (req) => { ${prelude} ${guard} return ${sink}; };`;
    const full = "if (u.protocol !== 'https:' || u.hostname !== 'a.com') throw new Error('no');";

    it("demotes an exact host and protocol check that dominates the request", () => {
      expectDemoted(code(full), "PG-SSRF-001");
      expect(findingsIn(code(full))[0]?.evidence).toMatch(/guard recognised at L\d+/);
      expectDemoted(
        code("if (u.protocol !== 'https:' || !new Set(['a.com']).has(u.hostname)) throw 1;"),
        "PG-SSRF-001",
      );
      expectDemoted(
        code(
          "",
          "null",
          "const u = new URL(req.query.u); if (u.hostname === 'a.com' && u.protocol === 'https:') { return fetch(u); }",
        ),
        "PG-SSRF-001",
      );
    });

    it("keeps full confidence for protocol-only, and low for host-only, or a different URL", () => {
      expectFires(code("if (u.protocol !== 'https:') throw 1;"), "PG-SSRF-001");
      const [hostOnly] = findingsIn(code("if (u.hostname !== 'a.com') throw 1;"));
      expect(hostOnly).toMatchObject({ ruleId: "PG-SSRF-001", confidence: "low" });
      expectFires(
        code(
          full.replaceAll("u.", "v."),
          "fetch(u)",
          "const u = new URL(req.query.u); const v = new URL('https://a.com');",
        ),
        "PG-SSRF-001",
      );
    });

    it("requires the guard to dominate and the URL to stay unchanged", () => {
      for (const source of [
        code("", `fetch(u); ${full}`),
        code(`if (req.query.s) { ${full} }`),
        code(`if (req.query.s) {} else { ${full} }`),
        code(`for (const x of [1]) { ${full} }`),
        code(`try { ${full} } catch (e) {}`),
        code(`${full} u.hostname = req.query.h;`),
        code(`${full} Object.assign(u, { hostname: req.query.h });`),
        code(`${full} u.href = req.query.h;`),
        code("", "fetch(u)", `let u = new URL(req.query.u); ${full} u = new URL(req.query.v);`),
      ])
        expectFires(source, "PG-SSRF-001");
    });

    const url = (rest: string) =>
      `export async function f(req: any) { const u = new URL(req.query.u);
       if (u.hostname !== 'a.com' || u.protocol !== 'https:') throw 1; ${rest} }`;

    it("keeps full confidence when an inner binding shadows the guarded URL", () => {
      expectDemoted(url("return fetch(u);"), "PG-SSRF-001");
      expectFires(url("for (const u of req.body.m) { await fetch(u); }"), "PG-SSRF-001");
      expectFires(url("{ const u = new URL(req.query.b); return fetch(u); }"), "PG-SSRF-001");
      expectFires(
        url(
          "switch (req.query.k) { case 'a': { const u = new URL(req.query.b); return fetch(u); } }",
        ),
        "PG-SSRF-001",
      );
      expectFires(
        url("switch (req.query.k) { case 'a': let u = new URL(req.query.b); return fetch(u); }"),
        "PG-SSRF-001",
      );
    });

    it("treats a repeated var as the same binding that is reassigned", () => {
      expectFires(
        `export async function f(req: any) { var u = new URL(req.query.u);
         if (u.hostname !== 'a.com' || u.protocol !== 'https:') throw 1;
         if (req.query.x) { var u = new URL(req.query.b); } return fetch(u); }`,
        "PG-SSRF-001",
      );
    });

    it("keeps full confidence when the URL is mutated through an alias or a helper", () => {
      expectFires(url("const v = u; v.hostname = req.query.h; return fetch(u);"), "PG-SSRF-001");
      expectFires(url("retarget(u, req.query.h); return fetch(u);"), "PG-SSRF-001");
      // a local helper that happens to be named like an HTTP verb is not a request
      expectFires(
        `const patch = (x: URL) => { x.host = 'evil'; };
         ${url("patch(u); return fetch(u);")}`,
        "PG-SSRF-001",
      );
      // property-path subject: handing the request root to a function invalidates the guard
      expectFires(
        `export async function f(req: any) {
         if (new URL(req.query.u).hostname !== 'a.com' || new URL(req.query.u).protocol !== 'https:') throw 1;
         normalize(req); return fetch(req.query.u); }`,
        "PG-SSRF-001",
      );
    });

    it("lets a logger, console or real HTTP client read the URL without invalidating the guard", () => {
      expectDemoted(url("console.log(u); return fetch(u);"), "PG-SSRF-001");
      expectDemoted(
        `import pino from 'pino'; const log = pino();
         ${url("log.info({ u }, 'go'); return fetch(u);")}`,
        "PG-SSRF-001",
      );
      expectDemoted(`import axios from 'axios'; ${url("return axios.get(u);")}`, "PG-SSRF-001");
    });

    it("requires the sink side of the subject to be stable too", () => {
      expectFires(
        `export async function f(req: any) { const v = new URL(req.query.u);
         if (v.hostname !== 'a.com' || v.protocol !== 'https:') throw 1;
         const w = new URL(v.href); register(w); return fetch(w); }`,
        "PG-SSRF-001",
      );
      expectDemoted(
        `export async function f(req: any) { const v = new URL(req.query.u);
         if (v.hostname !== 'a.com' || v.protocol !== 'https:') throw 1;
         const w = new URL(v.href); return fetch(w); }`,
        "PG-SSRF-001",
      );
    });

    it("keeps full confidence when a destructured URL object is passed to a helper", () => {
      const source = (middle: string) =>
        `export async function f(req: any) { const { u } = req.body;
         if (u.hostname !== 'a.com' || u.protocol !== 'https:') throw 1; ${middle} return fetch(u); }`;
      expectDemoted(source(""), "PG-SSRF-001");
      expectFires(source("retarget(u);"), "PG-SSRF-001");
    });

    it("keeps a fixed-host request with a user path as a low-confidence finding", () => {
      const [finding] = findingsIn(
        "export const f = (req) => fetch('https://api.example.com/u/' + req.params.id);",
      );
      expect(finding).toMatchObject({ ruleId: "PG-SSRF-001", confidence: "low" });
    });
  });

  it("does not resolve a const that is local to another function or assigned elsewhere", () => {
    const head = "import { exec } from 'child_process';";
    expectFires(
      `${head} function setup() { const dir = '/var/log'; return dir; }
       export const f = (req) => { exec('du -sh ' + dir); };
       export const g = (req) => { dir = req.query.d; };`,
      "PG-CMD-001",
    );
    expectFires(
      `${head} function setup() { const dir = '/var/log'; return dir; }
       export const f = (req) => { exec('du -sh ' + dir); }; globalThis.dir = req.query.d;`,
      "PG-CMD-001",
    );
    // a function-local constant used where it is declared is only inferred: demoted, not dropped
    expectDemoted(
      `${head} export function f() { const dir = '/var/log'; exec('du -sh ' + dir); }`,
      "PG-CMD-001",
    );
  });

  it("stays linear with thousands of guarded sinks in one function", () => {
    const build = (count: number) => {
      const lines = Array.from(
        { length: count },
        (_, index) =>
          `const p${index} = path.resolve(ROOT, req.query.a${index}); if (!p${index}.startsWith(ROOT + path.sep)) return res.end(); res.send(fs.readFileSync(p${index}));`,
      );
      return `import fs from 'fs'; import path from 'path'; const ROOT = path.resolve('x');
        export const f = (req, res) => {\n${lines.join("\n")}\n};`;
    };
    const small = bestTimeOf(3, () => analyzeJsSource(build(500), "a.ts"));
    const large = bestTimeOf(3, () => analyzeJsSource(build(2500), "a.ts"));
    // Every sink is guarded: each is kept at low confidence, none is silent.
    const findings = analyzeJsSource(build(20), "a.ts").findings;
    expect(findings).toHaveLength(20);
    expect(findings.every((finding) => finding.confidence === "low")).toBe(true);
    // 5x the input: linear is about 5, quadratic about 25. The floor keeps a loaded runner from
    // turning a tiny baseline into a noisy ratio.
    expect(large / Math.max(small, 20)).toBeLessThan(12);
  }, 120_000);
});
