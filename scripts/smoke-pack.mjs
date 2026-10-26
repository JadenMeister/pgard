#!/usr/bin/env node
// Installs the packed pgard tarball into a temporary prefix and exercises it the way a user
// would. Usage: node scripts/smoke-pack.mjs [path/to/pgard-<version>.tgz]
// No network sign-in is needed; `pgard doctor` only reads state and reports it.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const isWindows = process.platform === "win32";
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

const prefix = mkdtempSync(join(tmpdir(), "pgard-smoke-"));
let failures = 0;
function check(name, ok, detail = "") {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok || detail === "" ? "" : `: ${detail}`}`);
  if (!ok) failures += 1;
}
function run(file, args, options = {}) {
  return spawnSync(file, args, {
    encoding: "utf8",
    shell: isWindows,
    timeout: 120_000,
    ...options,
  });
}

try {
  const npm = isWindows ? "npm.cmd" : "npm";
  const install = run(npm, ["install", "--prefix", prefix, "--no-audit", "--no-fund", tarball]);
  check("npm install of the tarball", install.status === 0, install.stderr);
  if (install.status !== 0) throw new Error("install failed");

  const pkgDir = join(prefix, "node_modules", "pgard");
  const manifest = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  const bin = join(prefix, "node_modules", ".bin", isWindows ? "pgard.cmd" : "pgard");
  check("bin shim exists", existsSync(bin), bin);

  // doctor runs inside this repository checkout (a Git root); it never fails hard.
  const version = run(bin, ["--version"], { cwd: root });
  check(
    "pgard --version",
    version.stdout.trim() === `pgard ${manifest.version}`,
    version.stdout + version.stderr,
  );
  const help = run(bin, ["--help"], { cwd: root });
  check("pgard --help", help.status === 0 && help.stdout.includes("Usage:"), help.stderr);
  const rules = run(bin, ["rules", "list"], { cwd: root });
  check("pgard rules list", rules.status === 0 && rules.stdout.includes("PG-"), rules.stderr);
  // PGARD_SMOKE_SKIP_DOCTOR=1 is for a developer machine whose keychain doctor would read.
  const doctor =
    process.env.PGARD_SMOKE_SKIP_DOCTOR === "1"
      ? { status: 0, stdout: "Node.js Git (skipped)", stderr: "" }
      : run(bin, ["doctor"], { cwd: root });
  check(
    "pgard doctor",
    doctor.status === 0 && doctor.stdout.includes("Node.js") && doctor.stdout.includes("Git"),
    `exit ${doctor.status}\n${doctor.stdout}${doctor.stderr}`,
  );

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

  // Tree-sitter grammar from the installed package, with its pinned checksum.
  const grammar = await import(pathToFileURL(join(pkgDir, "dist", "smoke-grammar.js")).href);
  const wasmPath = grammar.grammarPath("python");
  check(
    "grammar path is inside the installed package",
    realpathSync(wasmPath).startsWith(realpathSync(pkgDir)),
    wasmPath,
  );
  const readme = readFileSync(join(pkgDir, "assets", "grammars", "README.md"), "utf8");
  const pinned = new RegExp("`tree-sitter-python\\.wasm`[^\\n]*?`([0-9a-f]{64})`").exec(
    readme,
  )?.[1];
  const actual = createHash("sha256").update(readFileSync(wasmPath)).digest("hex");
  check("python grammar matches its pinned SHA-256", pinned === actual, `${pinned} vs ${actual}`);
  const runtime = new grammar.TreeSitterRuntime();
  const parsed = await runtime.parse("python", "def f(x):\n    return x + 1\n");
  check(
    "tree-sitter parses Python",
    parsed.status === "parsed" && parsed.errorCount === 0,
    JSON.stringify(parsed.status),
  );
  if (parsed.status === "parsed") parsed.dispose();

  for (const file of [
    "NOTICE.md",
    "LICENSE",
    "assets/fonts/OFL.txt",
    "assets/grammars/LICENSE.tree-sitter-python",
  ]) {
    check(`ships ${file}`, existsSync(join(pkgDir, file)));
  }

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
