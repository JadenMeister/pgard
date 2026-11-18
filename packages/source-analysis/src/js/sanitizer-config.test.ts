import { describe, expect, it } from "vitest";
import { analyzeJsSource } from "./analyze-js.js";

const find = (code: string, ruleId: string, path = "src/a.ts") =>
  analyzeJsSource(code, path).findings.filter((finding) => finding.ruleId === ruleId);
const xss = (code: string) => find(code, "PG-XSS-001");
const DOMPURIFY = "import DOMPurify from 'dompurify';\n";
const SANITIZE_HTML = "import sanitizeHtml from 'sanitize-html';\n";

describe("sanitizer configuration that lets script through (#278)", () => {
  it("still suppresses a plain DOMPurify.sanitize and a plain sanitize-html call", () => {
    expect(xss(`${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash);`)).toEqual([]);
    expect(
      xss(
        `${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, { USE_PROFILES: { html: true } });`,
      ),
    ).toEqual([]);
    expect(
      xss(
        `${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, { ADD_TAGS: ['a-b'], ADD_ATTR: ['target'], ALLOWED_TAGS: ['b'] });`,
      ),
    ).toEqual([]);
    expect(
      xss(
        `${SANITIZE_HTML}el.innerHTML = sanitizeHtml(location.hash, { allowedTags: ['b', 'i'], allowedAttributes: { a: ['href'] } });`,
      ),
    ).toEqual([]);
    expect(
      xss(
        `${DOMPURIFY}DOMPurify.setConfig({ ALLOWED_TAGS: ['b'] });\nel.innerHTML = DOMPurify.sanitize(location.hash);`,
      ),
    ).toEqual([]);
  });

  it.each([
    ["an addHook", "DOMPurify.addHook('afterSanitizeAttributes', (n) => n);", "addHook"],
    ["a setConfig that adds script", "DOMPurify.setConfig({ ADD_TAGS: ['script'] });", "setConfig"],
    ["a setConfig with a config that is not visible", "DOMPurify.setConfig(cfg);", "setConfig"],
  ])("demotes, not drops, a sanitize call in a file with %s", (_label, setup, word) => {
    const [finding, ...rest] = xss(
      `${DOMPURIFY}${setup}\nel.innerHTML = DOMPurify.sanitize(location.hash);`,
    );
    expect(rest).toEqual([]);
    expect(finding?.confidence).toBe("low");
    expect(["low", "medium"]).toContain(finding?.severity);
    expect(finding?.evidence).toContain(word);
    expect(finding?.evidence).toContain("script or event handlers");
  });

  it.each([
    ["ADD_TAGS with script", "{ ADD_TAGS: ['script'] }"],
    ["ALLOWED_TAGS with an iframe", "{ ALLOWED_TAGS: ['b', 'iframe'] }"],
    ["ADD_ATTR with an event handler", "{ ADD_ATTR: ['onclick'] }"],
    ["ALLOWED_ATTR with an event handler", "{ ALLOWED_ATTR: ['href', 'onerror'] }"],
    ["RETURN_DOM_FRAGMENT", "{ RETURN_DOM_FRAGMENT: true }"],
    ["ALLOW_UNKNOWN_PROTOCOLS", "{ ALLOW_UNKNOWN_PROTOCOLS: true }"],
    ["a spread of such options", "{ ...{ ADD_TAGS: ['script'] } }"],
    ["a tag list that is not visible", "{ ADD_TAGS: someTags }"],
    ["an options object that is not visible", "someOptions"],
    ["a computed option name", "{ [key]: 1 }"],
  ])("demotes DOMPurify.sanitize given %s", (_label, options) => {
    const [finding] = xss(
      `${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, ${options});`,
    );
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain("script or event handlers");
  });

  it("reads a const options object and rejects a variable holding the unsafe result", () => {
    const [finding] = xss(
      `${DOMPURIFY}const cfg = { ADD_TAGS: ['script'] };\nconst clean = DOMPurify.sanitize(location.hash, cfg);\nel.innerHTML = clean;`,
    );
    expect(finding?.confidence).toBe("low");
    expect(
      xss(
        `${DOMPURIFY}const cfg = { ADD_TAGS: ['b'] };\nel.innerHTML = DOMPurify.sanitize(location.hash, cfg);`,
      ),
    ).toEqual([]);
  });

  it.each([
    ["allowedTags: false", "{ allowedTags: false }"],
    ["allowVulnerableTags: true", "{ allowVulnerableTags: true }"],
    ["allowedAttributes: false", "{ allowedAttributes: false }"],
    ["a script tag", "{ allowedTags: ['b', 'script'] }"],
    ["an event-handler attribute", "{ allowedAttributes: { '*': ['onclick'] } }"],
    ["a javascript scheme", "{ allowedSchemes: ['javascript'] }"],
  ])("demotes sanitize-html given %s", (_label, options) => {
    const [finding] = xss(
      `${SANITIZE_HTML}el.innerHTML = sanitizeHtml(location.hash, ${options});`,
    );
    expect(finding?.confidence).toBe("low");
    expect(finding?.evidence).toContain("script or event handlers");
  });

  it("does not let a DOMPurify hook change the verdict of an unrelated sanitizer", () => {
    expect(
      xss(
        `${SANITIZE_HTML}import other from 'other';\nother.addHook('x', () => 1);\nel.innerHTML = sanitizeHtml(location.hash);`,
      ),
    ).toEqual([]);
  });
});

describe("HTML escapers do not clean for non-XSS rules (#278)", () => {
  it("rates a shell command built with escapeHtml as critical", () => {
    const [finding] = find(
      "import { exec } from 'child_process';\nimport escapeHtml from 'escape-html';\napp.get('/x', (req, res) => { exec('cat ' + escapeHtml(req.query.file)); });",
      "PG-CMD-001",
    );
    expect(finding).toMatchObject({ severity: "critical", confidence: "high" });
  });

  it("rates SQL built with a local identity sanitize() as high", () => {
    const [finding] = find(
      "import { Pool } from 'pg';\nconst pool = new Pool();\nfunction sanitize(s) { return s; }\napp.get('/u', async (req, res) => { await pool.query(`SELECT * FROM users WHERE id = ${sanitize(req.query.id)}`); });",
      "PG-SQL-001",
    );
    expect(finding).toMatchObject({ severity: "high", confidence: "high" });
  });

  it("rates a path built with escape() as a finding", () => {
    const found = find(
      "import fs from 'fs';\napp.get('/f', (req, res) => { res.send(fs.readFileSync('/srv/' + escape(req.query.name))); });",
      "PG-PATH-001",
    );
    expect(found.length).toBeGreaterThan(0);
  });

  it("keeps a SQL escaper from a SQL module and numeric coercion clean", () => {
    const sqlstring = find(
      "import { Pool } from 'pg';\nimport { escape } from 'sqlstring';\nconst pool = new Pool();\napp.get('/u', async (req, res) => { await pool.query('SELECT * FROM t WHERE id = ' + escape(req.query.id)); });",
      "PG-SQL-001",
    );
    expect(sqlstring.every((finding) => finding.severity !== "high")).toBe(true);
    const handle = find(
      "import mysql from 'mysql';\nconst conn = mysql.createConnection({});\napp.get('/u', (req, res) => { conn.query('SELECT * FROM t WHERE id = ' + conn.escape(req.query.id)); });",
      "PG-SQL-001",
    );
    expect(handle.every((finding) => finding.severity !== "high")).toBe(true);
    const numeric = find(
      "import { Pool } from 'pg';\nconst pool = new Pool();\napp.get('/u', async (req, res) => { await pool.query(`SELECT * FROM t WHERE id = ${parseInt(req.query.id)}`); });",
      "PG-SQL-001",
    );
    expect(numeric.every((finding) => finding.severity !== "high")).toBe(true);
  });

  it("still treats an HTML escaper as clean for the XSS rule", () => {
    const [finding] = xss(
      "import escapeHtml from 'escape-html';\nel.innerHTML = '<p>' + escapeHtml(location.hash) + '</p>';",
    );
    expect(finding?.confidence).toBe("low");
  });

  it("keeps a parameterised query silent", () => {
    expect(
      find(
        "import { Pool } from 'pg';\nconst pool = new Pool();\napp.get('/u', async (req, res) => { await pool.query('SELECT * FROM t WHERE id = $1', [req.query.id]); });",
        "PG-SQL-001",
      ),
    ).toEqual([]);
  });
});

describe("attribute context after sanitizing (#278)", () => {
  it("keeps the rating of request input placed into an attribute through DOMPurify", () => {
    const [attribute] = xss(
      `${DOMPURIFY}el.innerHTML = "<a href='" + DOMPurify.sanitize(location.hash) + "'>x</a>";`,
    );
    expect(attribute).toMatchObject({ severity: "high", confidence: "medium" });
    expect(attribute?.evidence).toContain("attribute or URL context");
    const [template] = xss(
      `${DOMPURIFY}el.innerHTML = \`<img alt="\${DOMPurify.sanitize(location.hash)}">\`;`,
    );
    expect(template).toMatchObject({ severity: "high" });
  });

  it("leaves a sanitized value in a text context as before", () => {
    const [finding] = xss(
      `${DOMPURIFY}el.innerHTML = "<p>" + DOMPurify.sanitize(location.hash) + "</p>";`,
    );
    expect(finding?.severity).not.toBe("high");
  });
});

describe("XSS recall gaps (#274)", () => {
  it.each([
    ["innerHTML +=", "el.innerHTML += location.hash;"],
    ["outerHTML +=", "el.outerHTML += '<b>' + location.hash;"],
  ])("treats %s as a sink", (_label, code) => {
    const [finding] = xss(code);
    expect(finding).toMatchObject({ severity: "high" });
  });

  it("does not report a static += and still honours a proven sanitizer", () => {
    expect(xss("el.innerHTML += '<b>x</b>';")).toEqual([]);
    expect(xss(`${DOMPURIFY}el.innerHTML += DOMPurify.sanitize(location.hash);`)).toEqual([]);
  });

  it.each([
    ["this.$el", "class V { render(h) { this.$el.html(h + location.hash); } }"],
    ["a $el parameter", "function paint($el) { $el.html(location.hash); }"],
    ["this.$()", "class V { render() { this.$('.row').html(location.hash); } }"],
    [
      "an alias of this.$el",
      "class V { render() { const $el = this.$el; $el.append('<i>' + location.hash); } }",
    ],
  ])("treats %s as a jQuery receiver", (_label, code) => {
    expect(xss(code).length).toBe(1);
  });

  it("does not treat a non-jQuery $el as one", () => {
    expect(xss("const $el = cheerio.load(page);\n$el.html(location.hash);")).toEqual([]);
    expect(xss("import $el from 'cheerio-like';\n$el.html(location.hash);")).toEqual([]);
    expect(xss("class V { render() { this.el.html(location.hash); } }")).toEqual([]);
  });

  it("follows a spread whose props come from a helper's return value", () => {
    const helper =
      "function htmlProps(html) { return { className: 'x', dangerouslySetInnerHTML: { __html: html } }; }\n";
    const found = find(
      `${helper}export const A = ({ html }) => <div {...htmlProps(html)} />;`,
      "PG-XSS-002",
      "src/a.tsx",
    );
    expect(found.length).toBe(1);
    expect(found[0]?.evidence).toContain("parameters are not linked");
    const viaConst = find(
      `const arrow = (html) => ({ dangerouslySetInnerHTML: { __html: html } });\nexport const A = ({ html }) => { const p = arrow(html); return <div {...p} />; };`,
      "PG-XSS-002",
      "src/a.tsx",
    );
    expect(viaConst.length).toBe(1);
  });

  it("stays silent for a helper without the prop or with a sanitized value", () => {
    expect(
      find(
        "function props(h) { return { className: h }; }\nexport const A = ({ h }) => <div {...props(h)} />;",
        "PG-XSS-002",
        "src/a.tsx",
      ),
    ).toEqual([]);
    expect(
      find(
        `${DOMPURIFY}function props(h) { return { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(h) } }; }\nexport const A = ({ h }) => <div {...props(h)} />;`,
        "PG-XSS-002",
        "src/a.tsx",
      ),
    ).toEqual([]);
    expect(
      find(
        "import { props } from './p';\nexport const A = ({ h }) => <div {...props(h)} />;",
        "PG-XSS-002",
        "src/a.tsx",
      ),
    ).toEqual([]);
  });
});

describe("benign configuration is not noise (#278 review)", () => {
  const hash = "el.innerHTML = DOMPurify.sanitize(location.hash);";
  const html = (options: string) =>
    `${SANITIZE_HTML}el.innerHTML = sanitizeHtml(location.hash, ${options});`;

  it.each([
    [
      "a hook that sets target and rel",
      "DOMPurify.addHook('afterSanitizeAttributes', (n) => { n.setAttribute('target', '_blank'); n.setAttribute('rel', 'noopener'); });",
    ],
    [
      "a guarded hook",
      "DOMPurify.addHook('afterSanitizeAttributes', function (node) { if ('target' in node && node.tagName === 'A') { node.setAttribute('target', '_blank'); } else if (node.hasAttribute('x')) node.removeAttribute('x'); });",
    ],
    [
      "an arrow hook with an expression body",
      "DOMPurify.addHook('afterSanitizeAttributes', (n) => n.setAttribute('target', '_blank'));",
    ],
  ])("does not flag %s", (_label, hook) => {
    expect(xss(`${DOMPURIFY}${hook}\n${hash}`)).toEqual([]);
  });

  it.each([
    ["an event-handler attribute", "(n) => n.setAttribute('onclick', 'x()')"],
    ["a javascript: value", "(n) => n.setAttribute('href', 'javascript:x()')"],
    ["a non-constant value", "(n) => n.setAttribute('href', n.dataset.u)"],
    ["another function call", "(n) => { track(n); }"],
    ["an assignment", "(n) => { n.innerHTML = n.dataset.h; }"],
    ["a callback that is not inline", "someHook"],
    ["srcdoc", "(n) => n.setAttribute('srcdoc', '<b>')"],
  ])("still flags a hook with %s", (_label, callback) => {
    const [finding] = xss(`${DOMPURIFY}DOMPurify.addHook('x', ${callback});\n${hash}`);
    expect(finding?.confidence).toBe("low");
  });

  it.each([
    [
      "defaults spread",
      "{ allowedTags: [...sanitizeHtml.defaults.allowedTags, 'img'], allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, img: ['src'] } }",
    ],
    ["defaults concat", "{ allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']) }"],
    [
      "name and values entries",
      "{ allowedAttributes: { a: ['href', { name: 'target', values: ['_blank'] }] } }",
    ],
  ])("does not flag sanitize-html with %s", (_label, options) => {
    expect(xss(html(options))).toEqual([]);
  });

  it.each([
    [
      "a script added to the defaults",
      "{ allowedTags: [...sanitizeHtml.defaults.allowedTags, 'script'] }",
    ],
    [
      "a script added by concat",
      "{ allowedTags: sanitizeHtml.defaults.allowedTags.concat(['iframe']) }",
    ],
    ["a spread of something else", "{ allowedTags: [...others, 'img'] }"],
    [
      "an event name in a name entry",
      "{ allowedAttributes: { a: [{ name: 'onclick', values: ['x'] }] } }",
    ],
    ["an on* glob", "{ allowedAttributes: { '*': ['on*'] } }"],
    ["every attribute", "{ allowedAttributes: { a: ['*'] } }"],
    ["a script scheme by tag", "{ allowedSchemesByTag: { a: ['javascript'] } }"],
  ])("still flags sanitize-html with %s", (_label, options) => {
    const [finding] = xss(html(options));
    expect(finding?.confidence).toBe("low");
  });

  it("flags a catch-all ALLOWED_URI_REGEXP and a config object written through a member", () => {
    const [uri] = xss(
      `${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, { ALLOWED_URI_REGEXP: /.*/ });`,
    );
    expect(uri?.confidence).toBe("low");
    expect(
      xss(
        `${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, { ALLOWED_URI_REGEXP: /^(https?|mailto):/i });`,
      ),
    ).toEqual([]);
    const [mutated] = xss(
      `${DOMPURIFY}const cfg = { ADD_ATTR: ['target'] };\ncfg.ADD_TAGS = ['script'];\nel.innerHTML = DOMPurify.sanitize(location.hash, cfg);`,
    );
    expect(mutated?.confidence).toBe("low");
  });
});

describe("file-name sanitizers clean a path (#278 review)", () => {
  const path = (code: string) => find(code, "PG-PATH-001");
  const send = (name: string) =>
    `app.get('/f/:name', (req, res) => { res.sendFile(require('path').join(__dirname, 'uploads', ${name})); });`;

  it.each([
    [
      "sanitize-filename default import",
      "import sanitize from 'sanitize-filename';\n",
      "sanitize(req.params.name)",
    ],
    [
      "a renamed sanitize-filename",
      "import clean from 'sanitize-filename';\n",
      "clean(req.params.name)",
    ],
    [
      "a sanitize-filename require",
      "const clean = require('sanitize-filename');\n",
      "clean(req.params.name)",
    ],
    [
      "a filenamify named import",
      "import { filenamify } from 'filenamify';\n",
      "filenamify(req.params.name)",
    ],
    [
      "a filenamify default import",
      "import filenamify from 'filenamify';\n",
      "filenamify(req.params.name)",
    ],
  ])("keeps %s clean", (_label, imports, call) => {
    expect(path(`${imports}${send(call)}`)).toEqual([]);
  });

  it("still reports a local sanitize() and an unrelated sanitize import", () => {
    expect(
      path(`function sanitize(s) { return s; }\n${send("sanitize(req.params.name)")}`).length,
    ).toBeGreaterThan(0);
    expect(
      path(`import sanitize from 'some-html-lib';\n${send("sanitize(req.params.name)")}`).length,
    ).toBeGreaterThan(0);
  });
});

describe("new patterns stay linear and bounded (#278)", () => {
  it("reads a huge options object, many hooks and a long attribute prefix quickly", () => {
    const options = `{ ${Array.from({ length: 5000 }, (_, i) => `K${i}: ${i}`).join(", ")} }`;
    const hooks = "DOMPurify.addHook('x', f);\n".repeat(5000);
    const prefix = `'<a ${"b=".repeat(20000)}' + `;
    const started = Date.now();
    const result = [
      xss(`${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, ${options});`),
      xss(`${DOMPURIFY}${hooks}el.innerHTML = DOMPurify.sanitize(location.hash);`),
      xss(`${DOMPURIFY}el.innerHTML = ${prefix}DOMPurify.sanitize(location.hash);`),
    ];
    expect(Date.now() - started).toBeLessThan(5000);
    expect(result[0]?.length).toBe(1);
    expect(result[1]?.length).toBe(1);
    expect(result[2]?.length).toBe(1);
  });

  it("handles a modest nesting of options and helper calls", () => {
    const nested = `${"{ a: ".repeat(30)}1${" }".repeat(30)}`;
    expect(xss(`${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, ${nested});`)).toEqual(
      [],
    );
    const spreads = `${"{ ...".repeat(10)}{ ADD_TAGS: ['script'] }${" }".repeat(10)}`;
    expect(
      xss(`${DOMPURIFY}el.innerHTML = DOMPurify.sanitize(location.hash, ${spreads});`)[0]
        ?.confidence,
    ).toBe("low");
  });
});
