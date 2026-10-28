#!/usr/bin/env node
// Installs the packed pgard tarball into a temporary prefix and exercises it the way a user
// would. Usage: node scripts/smoke-pack.mjs [path/to/pgard-<version>.tgz]
// No network sign-in is needed; `pgard doctor` only reads state and reports it.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { npmCommand } from "./pack-lib.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packDir = join(root, ".pack");
const tarball =
  process.argv[2] === undefined
    ? join(
        packDir,
        readdirSync(packDir).find((name) => /^pgard-.*\.tgz$/.test(name)) ??
          (() => {
            throw new Error("no .pack/pgard-*.tgz; run npm run pack:pgard");
          })(),
      )
    : resolve(process.argv[2]);

// The directory name contains a space on purpose: a user path with a space must work everywhere.
const prefix = mkdtempSync(join(tmpdir(), "pgard smoke "));
let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok || detail === "" ? "" : `: ${detail}`}`);
  if (!ok) failures += 1;
}
// No shell anywhere: arguments are passed as an array, so paths with spaces need no quoting.
function run(file, args, options = {}) {
  return spawnSync(file, args, { encoding: "utf8", timeout: 120_000, ...options });
}

try {
  const npm = npmCommand();
  const install = run(npm.file, [
    ...npm.prefixArgs,
    "install",
    "--prefix",
    prefix,
    "--no-audit",
    "--no-fund",
    tarball,
  ]);
  check("npm install of the tarball", install.status === 0, install.stderr);
  if (install.status !== 0) throw new Error("install failed");

  const pkgDir = join(prefix, "node_modules", "pgard");
  const manifest = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  // The manifest of THIS tarball must carry the publishing metadata (see docs/RELEASING.md).
  check(
    "packed manifest is publishable",
    manifest.name === "pgard" &&
      manifest.private !== true &&
      manifest.license === "MIT" &&
      manifest.repository?.url === "git+https://github.com/JadenMeister/pgard.git" &&
      typeof manifest.homepage === "string" &&
      typeof manifest.bugs?.url === "string" &&
      typeof manifest.engines?.node === "string" &&
      Array.isArray(manifest.files) &&
      manifest.publishConfig?.access === "public" &&
      manifest.publishConfig?.provenance === true,
    JSON.stringify(manifest.publishConfig),
  );
  const shim = join(
    prefix,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "pgard.cmd" : "pgard",
  );
  check("bin shim exists", existsSync(shim), shim);
  // The shim is a .cmd file on Windows and needs a shell; run the bin target with this Node
  // instead, which is what the shim does.
  if (process.platform === "win32") {
    // The real shim once, through cmd.exe with the quoting cmd expects (the path has a space).
    const viaShim = run(
      process.env.ComSpec ?? "cmd.exe",
      ["/d", "/s", "/c", `""${shim}" --version"`],
      { windowsVerbatimArguments: true },
    );
    check(
      "pgard.cmd shim runs --version",
      viaShim.stdout.trim() === `pgard ${manifest.version}`,
      viaShim.stdout + viaShim.stderr,
    );
  }
  const binTarget = join(pkgDir, manifest.bin.pgard);
  const pgard = (args, options) => run(process.execPath, [binTarget, ...args], options);

  // doctor runs inside this repository checkout (a Git root); it never fails hard.
  const version = pgard(["--version"], { cwd: root });
  check(
    "pgard --version",
    version.stdout.trim() === `pgard ${manifest.version}`,
    version.stdout + version.stderr,
  );
  const help = pgard(["--help"], { cwd: root });
  check("pgard --help", help.status === 0 && help.stdout.includes("Usage:"), help.stderr);
  const rules = pgard(["rules", "list"], { cwd: root });
  check("pgard rules list", rules.status === 0 && rules.stdout.includes("PG-"), rules.stderr);
  // PGARD_SMOKE_SKIP_DOCTOR=1 is for a developer machine whose keychain doctor would read.
  if (process.env.PGARD_SMOKE_SKIP_DOCTOR === "1") {
    console.log("skip pgard doctor (PGARD_SMOKE_SKIP_DOCTOR=1)");
  } else {
    const doctor = pgard(["doctor"], { cwd: root });
    check(
      "pgard doctor",
      doctor.status === 0 && doctor.stdout.includes("Node.js") && doctor.stdout.includes("Git"),
      `exit ${doctor.status}\n${doctor.stdout}${doctor.stderr}`,
    );
  }

  // Korean PDF with the embedded Noto font; a silent Latin fallback fails.
  const report = await import(pathToFileURL(join(pkgDir, "dist", "smoke-report.js")).href);
  const fonts = report.loadPdfFonts();
  check("PDF fonts pass the pinned checksums", fonts.ok === true, fonts.reason);
  let fallback = "not called";
  const finding = {
    id: "f1",
    ruleId: "PG-SQL-001",
    title: "사용자 입력이 SQL 질의에 직접 연결됩니다",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/api/users.ts", line: 42, url: null, commit: null },
    evidence: "req.query -> string concat -> query() (value redacted)",
    impact: "공격자가 질의 구조를 바꿀 수 있습니다.",
    recommendation: "매개변수화된 쿼리를 사용하세요.",
    references: { cwe: ["CWE-89"], owasp: ["A05:2025"], cve: [] },
    sources: ["code"],
  };
  const pdf = await report.renderPdfReport(
    {
      schemaVersion: "1.0",
      scanId: "3f2b9c1e-aaaa-bbbb-cccc-000000000000",
      startedAt: "2026-10-24T01:02:03.000Z",
      finishedAt: "2026-10-24T01:02:09.000Z",
      tool: { name: "pgard", version: manifest.version },
      requestedScopes: ["code"],
      overallStatus: "completed",
      target: { repo: "owner/이름", revision: "abc123", webOrigin: null },
      authorization: { decision: "allowed", checks: [] },
      coverage: [],
      findings: [finding],
      advisoryDb: { version: null, updatedAt: null },
    },
    { compress: false, onFontFallback: (message) => (fallback = message) },
  );
  const text = pdf.toString("latin1");
  check("PDF render reports no font fallback", fallback === null, String(fallback));
  check(
    "PDF embeds the Noto Sans KR font",
    /\+NotoSansKR-Regular/.test(text) && /\+NotoSansKR-Bold/.test(text),
  );
  check("PDF has no Latin-1 replacement notice", !text.includes(report.PDF_REPLACEMENT_NOTICE));
  check("PDF does not use the Helvetica fallback", !/\/BaseFont \/Helvetica/.test(text));

  // Every tree-sitter grammar from the installed layout: path inside the package, pinned
  // checksum (the runtime's own check and the README's table), and a real parse.
  const grammar = await import(pathToFileURL(join(pkgDir, "dist", "smoke-grammar.js")).href);
  const readme = readFileSync(join(pkgDir, "assets", "grammars", "README.md"), "utf8");
  const samples = {
    java: "class A { int f(int x) { return x + 1; } }\n",
    kotlin: "fun f(x: Int): Int { return x + 1 }\n",
    python: "def f(x):\n    return x + 1\n",
    php: "<?php function f($x) { return $x + 1; }\n",
  };
  const runtime = new grammar.TreeSitterRuntime();
  for (const language of grammar.TREE_SITTER_LANGUAGES) {
    const wasmPath = grammar.grammarPath(language);
    check(
      `${language} grammar path is inside the installed package`,
      existsSync(wasmPath) && realpathSync(wasmPath).startsWith(realpathSync(pkgDir)),
      wasmPath,
    );
    const actual = createHash("sha256").update(readFileSync(wasmPath)).digest("hex");
    const inReadme = new RegExp(
      `\`tree-sitter-${language}\\.wasm\`[^\\n]*?\`([0-9a-f]{64})\``,
    ).exec(readme)?.[1];
    check(
      `${language} grammar matches the README SHA-256`,
      inReadme === actual,
      `${inReadme} vs ${actual}`,
    );
    const verified = grammar.readVerifiedGrammar(language);
    check(
      `${language} grammar passes the runtime checksum`,
      grammar.GRAMMAR_SHA256[language] === actual && verified.ok,
      verified.ok ? "" : verified.reason,
    );
    const parsed = await runtime.parse(language, samples[language]);
    check(
      `tree-sitter parses ${language}`,
      parsed.status === "parsed" && parsed.errorCount === 0,
      JSON.stringify(parsed.status),
    );
    if (parsed.status === "parsed") parsed.dispose();
  }
  // A corrupted grammar must be refused, never parsed with.
  const corruptDir = mkdtempSync(join(prefix, "corrupt "));
  for (const language of grammar.TREE_SITTER_LANGUAGES) {
    const bytes = readFileSync(grammar.grammarPath(language));
    bytes[bytes.length >> 1] ^= 0xff;
    const corrupt = join(corruptDir, `tree-sitter-${language}.wasm`);
    writeFileSync(corrupt, bytes);
    const outcome = await new grammar.TreeSitterRuntime(() => corrupt).parse(
      language,
      samples[language],
    );
    check(
      `corrupted ${language} grammar is refused`,
      outcome.status === "unavailable" && /SHA-256/.test(outcome.reason),
      JSON.stringify(outcome.status),
    );
  }

  // The installed package scans a Python project offline: the grammar is read from assets/, both
  // Python rules fire, and the coverage says what was and was not checked.
  const pyProject = mkdtempSync(join(prefix, "py project "));
  writeFileSync(join(pyProject, "requirements.txt"), "Flask==3.0\n");
  writeFileSync(
    join(pyProject, "app.py"),
    [
      "import os",
      "import sqlite3",
      "from flask import Flask, request",
      "app = Flask(__name__)",
      "@app.route('/u')",
      "def u():",
      "    sqlite3.connect('x.db').cursor().execute(f\"SELECT * FROM t WHERE a = '{request.args['a']}'\")",
      "    os.system('ping ' + request.args['h'])",
      "    return ''",
      "",
    ].join("\n"),
  );
  const pyScan = await grammar.scanSourceCode(pyProject);
  const pyRules = pyScan.findings.map((item) => item.ruleId).sort();
  check(
    "installed package finds Python SQL injection and command execution",
    pyRules.join(",") === "PG-CMD-004,PG-SQL-006",
    pyRules.join(","),
  );
  const pyCoverage = pyScan.coverage.find((item) => item.area === "source:python");
  check(
    "Python coverage is completed and names Flask",
    pyCoverage?.status === "completed" && /frameworks: Flask/.test(pyCoverage.note ?? ""),
    JSON.stringify(pyCoverage),
  );
  check(
    "Python categories without rules are reported as not tested",
    pyScan.coverage.some(
      (item) => item.area === "source:python:other-categories" && item.status === "not_tested",
    ),
  );

  // JavaScript and Go run in the per-file analysis worker (dist/source-worker.js): the packed
  // scan must start it and keep its findings, and a file that overruns the limit is reported.
  const jsProject = mkdtempSync(join(prefix, "js project "));
  writeFileSync(
    join(jsProject, "db.js"),
    'const { Pool } = require("pg");\nconst pool = new Pool();\nexports.q = (req) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n',
  );
  writeFileSync(
    join(jsProject, "slow.go"),
    `package main\nfunc f() {\n${"var a\n".repeat(150000)}}\n`,
  );
  const jsScan = await grammar.scanSourceCode(jsProject, { perFileTimeLimitMs: 1000 });
  const jsCoverage = jsScan.coverage.find((entry) => entry.area === "source:javascript");
  const goCoverage = jsScan.coverage.find((entry) => entry.area === "source:go");
  check(
    "installed package analyzes JavaScript in the worker",
    jsScan.findings.some((item) => item.ruleId === "PG-SQL-001") &&
      jsCoverage?.status === "completed",
    JSON.stringify(jsCoverage),
  );
  check(
    "a file over the per-file limit is stopped and reported, not left hanging",
    goCoverage?.status === "partial" && /per-file limit/.test(goCoverage.note ?? ""),
    JSON.stringify(goCoverage),
  );

  // A PHP project scanned from the installed layout, offline: the scanner only reads files, and
  // nothing is stored (PGARD_NO_STORE) or sent anywhere. The PHP grammar must load from assets/.
  process.env.PGARD_NO_STORE = "1";
  const phpProject = mkdtempSync(join(prefix, "php project "));
  writeFileSync(
    join(phpProject, "composer.json"),
    JSON.stringify({ require: { "laravel/framework": "^11" } }),
  );
  writeFileSync(
    join(phpProject, "users.php"),
    "<?php\nfunction find($conn) { return mysqli_query($conn, \"SELECT * FROM users WHERE name = '\" . $_GET['name'] . \"'\"); }\n",
  );
  writeFileSync(
    join(phpProject, "ping.php"),
    "<?php\nfunction ping() { system(\"ping -c 1 \" . $_GET['host']); }\n",
  );
  writeFileSync(
    join(phpProject, "safe.php"),
    "<?php\nfunction safe($pdo) { $s = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $s->execute([$_GET['id']]); }\n",
  );
  const phpScan = await grammar.scanSourceCode(phpProject);
  const phpRules = phpScan.findings.map((item) => `${item.ruleId}@${item.location.path}`).sort();
  check(
    "PHP project scan finds the SQL and command injection and not the prepared statement",
    JSON.stringify(phpRules) === JSON.stringify(["PG-CMD-005@ping.php", "PG-SQL-007@users.php"]),
    JSON.stringify(phpRules),
  );
  const phpCoverage = phpScan.coverage.find((entry) => entry.area === "source:php");
  check(
    "PHP coverage is completed, names Laravel and says what is not checked",
    phpCoverage?.status === "completed" &&
      phpCoverage.ruleIds.join() === "PG-SQL-007,PG-CMD-005" &&
      phpCoverage.note.includes("Laravel") &&
      phpCoverage.note.includes("Not checked yet for PHP"),
    JSON.stringify(phpCoverage),
  );
  const phpRulesList = pgard(["rules", "list", "--language", "php"], { cwd: root });
  check(
    "pgard rules list --language php",
    phpRulesList.status === 0 &&
      phpRulesList.stdout.includes("PG-SQL-007") &&
      phpRulesList.stdout.includes("PG-CMD-005"),
    phpRulesList.stderr,
  );

  for (const file of [
    "NOTICE.md",
    "LICENSE",
    "assets/fonts/OFL.txt",
    "assets/grammars/LICENSE.tree-sitter-python",
    "assets/grammars/LICENSE.tree-sitter-php",
  ]) {
    check(`ships ${file}`, existsSync(join(pkgDir, file)));
  }

  const notice = readFileSync(join(pkgDir, "NOTICE.md"), "utf8");
  check(
    "shipped NOTICE.md names the packed asset paths",
    notice.includes("`assets/fonts/OFL.txt`") &&
      notice.includes("`assets/grammars/`") &&
      !notice.includes("`packages/report/fonts/OFL.txt`") &&
      existsSync(join(pkgDir, "assets", "fonts", "OFL.txt")),
  );

  // Dashboard server: started the way `pgard dashboard` starts it, no sign-in and no network.
  await new Promise((done) => {
    const child = spawn(
      process.execPath,
      [join(pkgDir, "dist", "dashboard.js"), "--project-root", root, "--no-browser"],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let finished = false;
    const finish = (name, ok, detail) => {
      if (finished) return;
      finished = true;
      check(name, ok, detail);
      clearTimeout(timer);
      child.kill();
      done();
    };
    const timer = setTimeout(
      () => finish("dashboard starts", false, `timeout; output: ${out}`),
      30_000,
    );
    child.stderr.on("data", (chunk) => (out += chunk));
    child.on("exit", (code) => finish("dashboard starts", false, `exited ${code}; output: ${out}`));
    child.stdout.on("data", async (chunk) => {
      out += chunk;
      const url = /https?:\/\/127\.0\.0\.1:\d+\/?/.exec(out)?.[0];
      if (url === undefined || finished) return;
      try {
        const response = await fetch(url);
        const html = await response.text();
        const csp = response.headers.get("content-security-policy") ?? "";
        finish(
          "dashboard serves index.html with a CSP header",
          response.status === 200 && html.includes("<div id=") && csp.includes("default-src"),
          `status ${response.status}, csp ${JSON.stringify(csp)}`,
        );
      } catch (error) {
        finish("dashboard serves index.html with a CSP header", false, String(error));
      }
    });
  });
} catch (error) {
  if (!(error instanceof Error && error.message === "install failed")) {
    console.error(error);
    failures += 1;
  }
} finally {
  rmSync(prefix, { recursive: true, force: true });
}

if (failures > 0) {
  console.error(`smoke-pack: ${failures} check(s) failed`);
  process.exit(1);
}
console.log("smoke-pack: all checks passed");
