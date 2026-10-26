import { describe, expect, it } from "vitest";
import { analyzeVueSource } from "../vue/analyze-vue.js";
import { analyzeJsSource } from "./analyze-js.js";

const rulesIn = (code: string, path = "src/app.ts") =>
  analyzeJsSource(code, path).findings.map((finding) => finding.ruleId);
const findingsIn = (code: string, path = "src/app.ts") => analyzeJsSource(code, path).findings;

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
    expect(bestTimeOf(3, () => analyzeJsSource(code, "big.js"))).toBeLessThan(5000);
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
    const code = Array.from(
      { length: 8000 },
      (_, index) =>
        `function f${index}(req) { const password = req.body.p${index}; el.innerHTML = x${index}; return check(password); }`,
    ).join("\n");
    expect(code.length).toBeGreaterThan(500_000);
    let analysis = analyzeJsSource(code, "big.js");
    expect(
      bestTimeOf(3, () => {
        analysis = analyzeJsSource(code, "big.js");
      }),
    ).toBeLessThan(5000);
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
