import { existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanGitHistory } from "./scan-history.js";
import { detectSecrets, isEnvironmentFile } from "./secret-patterns.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

// Fake, runtime-assembled values (nothing secret-looking is committed to this repo).
const join = (...parts: string[]) => parts.join("");
const FAKE = {
  github: join("ghp", "_", "Zq8", "aB3cD4eF5g", "Lm4", "hJ6kL7mN8p", "Pw7", "qR9sT0uV1w"),
  aws: join("AKIA", "Q7RT", "M2XW", "9KDP", "L3VZ"),
  stripe: join("sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc"),
  dbPassword: join("Xq9", "!vR2", "#mT7", "pLw4"),
  removed: join("ghp", "_", "R3mOv3dT0k3n", "AbCdEfGhIjKl", "MnOpQrStUvWxYz"),
  pem: join(
    "-----BEGIN ",
    "RSA ",
    "PRIVATE KEY-----\nMIIEow",
    "IBAAKCAQEA\n-----END ",
    "RSA PRIVATE KEY-----\n",
  ),
};
const ALL_VALUES = Object.values(FAKE).filter((value) => !value.includes("PRIVATE"));

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

const byRule = (result: Awaited<ReturnType<typeof scanGitHistory>>, ruleId: string) =>
  result.findings.filter((finding) => finding.ruleId === ruleId);

describe("detectSecrets", () => {
  it.each([
    ["github", `const t = "${FAKE.github}";`, "github_token"],
    ["aws", `key=${FAKE.aws}`, "aws_access_key_id"],
    ["stripe", `STRIPE=${FAKE.stripe}`, "stripe_key"],
    ["pem", FAKE.pem, "private_key"],
    ["generic", `DB_PASSWORD="${FAKE.dbPassword}"`, "generic_credential"],
    [
      "aws secret",
      `aws_secret_access_key = ${join("wJalr", "XUtnFEMI", "K7MDENG", "bPxRfiCY", "Q9z8Rk3mN2pL")}`,
      "aws_secret_access_key",
    ],
  ])("detects %s", (_label, text, kind) => {
    expect(detectSecrets(text).map((secret) => secret.kind)).toContain(kind);
  });

  it.each([
    ['password = "password"'],
    ["password: ${DB_PASSWORD}"],
    ["password = process.env.DB_PASSWORD"],
    ['api_key = "your-api-key-here"'],
    ["secret = changeme123"],
    [`key=${join("AKIA", "IOSFODNN7", "EXAMPLE")}`],
    ['password = "aaaaaaaaaaaa"'],
    ["token = config.auth.token"],
  ])("ignores placeholders and low-entropy values: %s", (text) => {
    expect(detectSecrets(text)).toEqual([]);
  });

  it("reports line numbers", () => {
    expect(detectSecrets(`a\nb\nx = "${FAKE.github}"`)[0]?.line).toBe(3);
  });

  // Regressions from scanning PGARD itself: code that names credentials is not an assignment.
  it.each([
    ["ternary between string literals", 'ruleId: commit ? "PG-SECRET-003" : "PG-SECRET-002",'],
    ["generic type annotation", "export const SECRET_KIND_LABEL: Record<SecretKind, string> = {"],
    ["parameter type", "  set(key: CredentialKey, secret: string): Promise<void>;"],
    ["parameter type (password)", "  setPassword(password: string): Promise<void>;"],
    ["regex literal", "const PASSWORD_TEXT = /pass(word)?|pwd/i;"],
    ["anchored regex literal", "const PASSWORD_NAME = /^(password|passwd|pwd|newPassword)$/i;"],
    ["regex in an object", "updatesPassword: /\\.update\\([^)]{0,200}(pass(word)?|pwd)/i.test(t),"],
    [
      "arrow function parameters",
      "const checkPassword = (object: ts.ObjectLiteralExpression) => {",
    ],
    ["constant reference", "        access_token: ACCESS_TOKEN,"],
    ["constant reference (camel key)", "    accessToken: GITHUB_ACCESS_TOKEN,"],
  ])("ignores %s in source code", (_label, text) => {
    expect(detectSecrets(text, { path: "src/module.ts" })).toEqual([]);
    expect(detectSecrets(text, { path: "internal/scan/module.go" })).toEqual([]);
  });

  // Review of #142: config values may contain any character, so the code-shape rules apply only
  // to code in source files, never to config files or to string literals inside source files.
  it.each([
    ["properties value with )", "db.password=Tr0ub4dor)xK9!qZ", "config/app.properties"],
    ["env value with ]", "DB_PASSWORD=hunter2]Zq9xLmWv", ".env"],
    ["env value with <", "DB_PASSWORD=Pass<word9xLmWv", ".env"],
    ["env value with >", "API_KEY=K9x>mQ2vLp8Wz4Rt", ".env"],
    ["YAML value with brackets", "password: K9x[mQ2]vLp8Wz4Rt", "config/app.yaml"],
    ["YAML value ending in :", "password: K9xmQ2vLp8Wz4Rt:", "config/app.yml"],
    ["properties value starting with /", "secret=/K9x|mQ2vLp8Wz4Rt", "app.properties"],
    ["all-caps env value", "PASSWORD=PROD_DB_PASSWORDX", ".env"],
    ["all-caps env passphrase", "SECRET_KEY=CORRECT_HORSE_BATTERY_STAPLE", ".env.production"],
    [
      "C# connection string",
      'var c = "Server=db;User Id=sa;Password=QwErTyUiOpAsDfGh;";',
      "src/Db.cs",
    ],
    ["Python DSN", 'DSN = "host=db user=app password=QwErTyUiOpAsDfGh"', "app/db.py"],
    [
      "URL query in TypeScript",
      'const u = "mysql://u@h/db?password=QwErTyUiOpAsDfGh";',
      "src/db.ts",
    ],
    ["PHP DSN", '$dsn = "pgsql:host=db;password=QwErTyUiOpAsDfGh";', "src/db.php"],
    ["template literal", "const c = `Password=QwErTyUiOpAsDfGh;`;", "src/db.ts"],
    ["code-shaped value in a string", 'const c = "password=Tr0ub4dor)xK9!qZ";', "src/db.ts"],
    // Re-review of #142: later lines of multi-line strings are not code.
    [
      "multi-line template literal",
      "const c = `\nServer=db;Password=QwErTyUiOpAsDfGh;\n`;",
      "src/db.ts",
    ],
    [
      "multi-line template literal with brackets",
      "const c = `\nPassword=K9x[mQ2]vLp8Wz4Rt;\n`;",
      "src/db.ts",
    ],
    ["Python triple-quoted block", 'CFG = """\npassword=QwErTyUiOpAsDfGh\n"""', "app.py"],
    ["Python triple-quoted brackets", 'CFG = """\npassword=K9x[mQ2]vLp8Wz4Rt\n"""', "app.py"],
    ["Ruby heredoc", "cfg = <<~EOS\n  password: K9x[mQ2]vLp8Wz4Rt\nEOS", "app.rb"],
    ["Go raw string", "cfg := `\npassword=K9x[mQ2]vLp8Wz4Rt\n`", "main.go"],
    ["Go raw string with all caps", "cfg := `\nPASSWORD=PROD_DB_PASSWORDX\n`", "main.go"],
    [
      "string after a regex literal holding a quote",
      'const re = /"/; const c = "Password=QwErTyUiOpAsDfGh";',
      "src/db.ts",
    ],
  ])("detects %s", (_label, text, path) => {
    expect(detectSecrets(text, { path }).map((secret) => secret.kind)).toContain(
      "generic_credential",
    );
  });

  it("ignores bare identifiers only where the line clearly is code", () => {
    expect(detectSecrets("connect(password=userSuppliedValue)", { path: "app/db.py" })).toEqual([]);
    expect(detectSecrets("const x = { password: passwordFromVault };", { path: "a.ts" })).toEqual(
      [],
    );
    // Ambiguous (could be a line inside a multi-line string): reported.
    const line = "password = userSuppliedValue";
    expect(detectSecrets(line, { path: "app/settings.py" }).map((s) => s.kind)).toEqual([
      "generic_credential",
    ]);
    expect(detectSecrets(line, { path: "config/app.ini" }).map((s) => s.kind)).toEqual([
      "generic_credential",
    ]);
    expect(detectSecrets("PASSWORD=abcdefghXYZ", { path: ".env" }).map((s) => s.kind)).toEqual([
      "generic_credential",
    ]);
  });

  it.each([
    ["quoted password", 'password = "hunter2xyzQ7"', "src/db.ts"],
    ["quoted password in Go", 'const password = "hunter2xyzQ7"', "main.go"],
    ["JSON key", '{ "client_secret": "Zx81kQp0Lm2N" }', "config.json"],
    ["env line", `DB_PASSWORD=${FAKE.dbPassword}`, ".env"],
    ["env line with export", "export API_KEY=abcdef123456XYZ", "deploy.sh"],
    ["unquoted YAML", "api_key: abcdef123456XYZ", "config.yml"],
    ["connection string in code", 'const url = "Server=db;Password=Abc123xyz9;";', "src/db.ts"],
    ["password with symbols", "password=(hunter2)xyz", ".env"],
  ])("still detects %s", (_label, text, path) => {
    expect(detectSecrets(text, { path }).map((secret) => secret.kind)).toContain(
      "generic_credential",
    );
  });

  it("still detects a quoted Stripe key assignment", () => {
    const text = `api_key: "${FAKE.stripe}"`;
    expect(detectSecrets(text, { path: "src/pay.ts" }).map((secret) => secret.kind)).toContain(
      "stripe_key",
    );
  });

  it("treats a private key header without a body as a header, not a key", () => {
    const header = join("-----BEGIN ", "PRIVATE KEY-----");
    const repeated = `["begin headers", "${header}\\n".repeat(5_000)],`;
    expect(detectSecrets(repeated).map((secret) => secret.kind)).toEqual(["private_key_header"]);
    const emptyBlock = `${header}\n${join("-----END ", "PRIVATE KEY-----")}\n`;
    expect(detectSecrets(emptyBlock).map((secret) => secret.kind)).toEqual(["private_key_header"]);
    expect(detectSecrets(FAKE.pem).map((secret) => secret.kind)).toEqual(["private_key"]);
  });
});

describe("isEnvironmentFile", () => {
  it.each([".env", "config/.env.local", ".env.production", "prod.env"])("matches %s", (file) => {
    expect(isEnvironmentFile(file)).toBe(true);
  });
  it.each([".env.example", ".env.sample", ".env.template", "env.ts", "environment.js"])(
    "ignores %s",
    (file) => {
      expect(isEnvironmentFile(file)).toBe(false);
    },
  );
});

describe("scanGitHistory", () => {
  it("reports a key header without a body as suspected with low confidence, a key as critical", async () => {
    fixture = createGitFixture();
    const header = join("-----BEGIN ", "PRIVATE KEY-----");
    fixture.commit({
      files: { "src/pem.ts": `export const HEADER = "${header}\\n";\n`, "key.pem": FAKE.pem },
    });
    const tracked = byRule(await scanGitHistory(fixture.root), "PG-SECRET-002");
    expect(tracked.find((finding) => finding.location.path === "src/pem.ts")).toMatchObject({
      severity: "high",
      status: "suspected",
      confidence: "low",
      evidence: "private key header without a key body in a tracked file (value redacted)",
    });
    expect(tracked.find((finding) => finding.location.path === "key.pem")).toMatchObject({
      severity: "critical",
      status: "confirmed",
      confidence: "high",
    });
  });

  it("reports committed .env files and tracked secrets at HEAD without values", async () => {
    fixture = createGitFixture();
    fixture.commit({
      files: {
        ".env": `DB_PASSWORD=${FAKE.dbPassword}\n`,
        ".env.example": "DB_PASSWORD=changeme\n",
        "src/config.ts": `export const token = "${FAKE.github}";\nexport const aws = "${FAKE.aws}";\n`,
      },
    });
    const result = await scanGitHistory(fixture.root);

    const envFindings = byRule(result, "PG-SECRET-001");
    expect(envFindings).toHaveLength(1);
    expect(envFindings[0]?.location).toMatchObject({ kind: "file", path: ".env", commit: null });

    const tracked = byRule(result, "PG-SECRET-002");
    expect(tracked.map((finding) => [finding.location.path, finding.location.line])).toEqual(
      expect.arrayContaining([
        [".env", 1],
        ["src/config.ts", 1],
        ["src/config.ts", 2],
      ]),
    );
    expect(tracked.find((finding) => finding.location.path === "src/config.ts")).toMatchObject({
      status: "confirmed",
      confidence: "high",
      sources: ["history"],
    });

    const json = JSON.stringify(result);
    for (const value of ALL_VALUES) expect(json).not.toContain(value);
    expect(result.coverage.map((entry) => [entry.area, entry.status])).toEqual([
      ["history:tracked-files", "completed"],
      ["history:commits", "completed"],
    ]);
  });

  it("does not report untracked or ignored local .env files", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { ".gitignore": ".env\n", "README.md": "x" } });
    writeFileSync(path.join(fixture.root, ".env"), `DB_PASSWORD=${FAKE.dbPassword}\n`);
    writeFileSync(path.join(fixture.root, "local.env"), `TOKEN=${FAKE.github}\n`);
    const result = await scanGitHistory(fixture.root);
    expect(result.findings).toEqual([]);
  });

  it("reports secrets and .env files that were removed but remain in history", async () => {
    fixture = createGitFixture();
    const introduced = fixture.commit({
      files: {
        "deploy.sh": `export GH="${FAKE.removed}"\n`,
        ".env": `DB_PASSWORD=${FAKE.dbPassword}\n`,
      },
    });
    fixture.commit({ remove: ["deploy.sh", ".env"], files: { "README.md": "cleaned" } });
    fixture.commit({ files: { "README.md": "later" } });
    const result = await scanGitHistory(fixture.root);

    const removed = byRule(result, "PG-SECRET-003");
    expect(removed.map((finding) => finding.location)).toEqual(
      expect.arrayContaining([
        { kind: "commit", path: "deploy.sh", line: 1, url: null, commit: introduced },
        { kind: "commit", path: ".env", line: 1, url: null, commit: introduced },
      ]),
    );
    expect(byRule(result, "PG-SECRET-001")).toEqual([
      expect.objectContaining({
        location: expect.objectContaining({ path: ".env", commit: introduced }),
      }),
    ]);
    expect(byRule(result, "PG-SECRET-002")).toEqual([]);
    const json = JSON.stringify(result);
    for (const value of ALL_VALUES) expect(json).not.toContain(value);
  });

  it("does not report a current secret again as a history finding", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "a.ts": `const t = "${FAKE.github}";\n` } });
    fixture.commit({ files: { "a.ts": `// moved\nconst t = "${FAKE.github}";\n` } });
    const result = await scanGitHistory(fixture.root);
    expect(byRule(result, "PG-SECRET-003")).toEqual([]);
    expect(byRule(result, "PG-SECRET-002")).toHaveLength(1);
  });

  it("marks coverage partial when the commit or size limits are reached", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "big.txt": `${"x".repeat(5000)}\n` } });
    fixture.commit({ files: { "a.txt": "1" } });
    fixture.commit({ files: { "a.txt": "2" } });
    const result = await scanGitHistory(fixture.root, { maxCommits: 2, maxBlobBytes: 1000 });
    const coverage = Object.fromEntries(result.coverage.map((entry) => [entry.area, entry]));
    expect(coverage["history:tracked-files"]?.status).toBe("partial");
    expect(coverage["history:commits"]?.status).toBe("partial");
    expect(coverage["history:commits"]?.note).toMatch(/most recent 2 commits/);
  });

  it("skips binary blobs and never runs repository-defined programs", async () => {
    fixture = createGitFixture();
    fixture.commit({
      files: {
        "img.bin": "\u0000\u0001binary",
        "a.txt": "x\n",
        ".gitattributes": "*.txt filter=pwn diff=pwn\n",
      },
    });
    const markerDir = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-hist-marker-")));
    try {
      const marker = path.join(markerDir, "ran");
      fixture.git("config", "filter.pwn.clean", `touch ${marker}; cat`);
      fixture.git("config", "diff.pwn.textconv", `touch ${marker}; cat`);
      const result = await scanGitHistory(fixture.root);
      expect(result.findings).toEqual([]);
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(markerDir, { recursive: true, force: true });
    }
  });

  it("emits one PG-HYGIENE-001 suggestion for committed dependency directories, by tracked paths only", async () => {
    fixture = createGitFixture();
    fixture.commit({
      files: {
        "package.json": '{ "name": "app" }\n',
        "node_modules/pkg/index.js": `const DB_PASSWORD = "${FAKE.dbPassword}";\n`,
        "node_modules/pkg/node_modules/dep/index.js": "module.exports = 1;\n",
        "packages/web/node_modules/x/index.js": "module.exports = 2;\n",
      },
    });
    // Untracked local dependency directories are never read.
    fixture.writeFile("vendor/local/untracked.php", "<?php\n");
    const result = await scanGitHistory(fixture.root);
    const hygiene = byRule(result, "PG-HYGIENE-001");
    expect(hygiene).toHaveLength(1);
    expect(hygiene[0]).toMatchObject({
      title: "Dependency directory committed to Git",
      severity: "info",
      status: "informational",
      context: "vendored",
      location: { kind: "file", path: "node_modules/", line: null, commit: null },
    });
    expect(hygiene[0]?.evidence).toContain("2 dependency directories are tracked in commit");
    expect(hygiene[0]?.evidence).toContain(
      "node_modules/ (2 tracked files), packages/web/node_modules/ (1 tracked file)",
    );
    expect(hygiene[0]?.evidence).not.toContain("vendor");
    expect(hygiene[0]?.recommendation).toContain(
      "git rm -r --cached node_modules packages/web/node_modules",
    );
    // The secret in the vendored file is still reported (the scan engine groups it later).
    expect(byRule(result, "PG-SECRET-002").map((finding) => finding.location.path)).toEqual([
      "node_modules/pkg/index.js",
    ]);
    expect(result.coverage[0]?.ruleIds).toContain("PG-HYGIENE-001");
    expect(result.coverage.map((entry) => entry.status)).toEqual(["completed", "completed"]);
  });

  it("does not emit PG-HYGIENE-001 without a committed dependency directory or for Go module vendoring", async () => {
    fixture = createGitFixture();
    fixture.commit({
      files: { "src/vendored.ts": "export {};\n", "my_node_modules_x/a.js": "1\n" },
    });
    expect(byRule(await scanGitHistory(fixture.root), "PG-HYGIENE-001")).toEqual([]);
    fixture.commit({
      files: {
        "go.mod": "module example.com/app\n",
        "vendor/modules.txt": "# github.com/pkg/errors v0.9.1\n",
        "vendor/github.com/pkg/errors/errors.go": "package errors\n",
      },
    });
    expect(byRule(await scanGitHistory(fixture.root), "PG-HYGIENE-001")).toEqual([]);
  });
});
