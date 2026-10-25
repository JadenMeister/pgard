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

  // #145: false negatives on main. Every case is a credential and must be reported.
  const L = "QwErTyUiOpAsDfGh";
  const C = "K9x[mQ2]vLp8Wz4Rt";
  const expectCredential = (text: string, path: string) =>
    expect(detectSecrets(text, { path }).map((secret) => secret.kind)).toContain(
      "generic_credential",
    );

  it.each([
    ["Python block with comma params", `DSN = """\nhost=db,password=${C},port=5432\n"""`, "a.py"],
    ["Python block, letters only", `DSN = '''\nhost=db,password=${L},port=5432\n'''`, "a.py"],
    ["YAML flow mapping in a template", `const y = \`\n{password: ${C}, user: a}\n\`;`, "a.ts"],
    ["YAML key with a comma in a template", `const y = \`\npassword: ${C},\n\`;`, "a.ts"],
    ["code-like line in a template", `const y = \`\nconst password = ${C};\n\`;`, "a.ts"],
    ["template after an interpolation", `const y = \`\${a}\n{password: ${C}}\n\`;`, "a.ts"],
    [
      "string after a regex literal with a quote",
      `const r = /"/; const c = "x,password=${C}";`,
      "a.ts",
    ],
    [
      "template after a regex with a backtick",
      `const r = /\`/;\nconst c = \`\n{password: ${C}}\`;`,
      "a.ts",
    ],
    [
      "template after a comment with a backtick",
      `// a \` b\nconst c = \`\n{password: ${C}}\`;`,
      "a.ts",
    ],
    ["Go raw string with parens", `cfg := \`\n(password=${C})\n\``, "main.go"],
    ["Ruby heredoc flow mapping", `cfg = <<~EOS\n  {password: ${C}}\nEOS`, "app.rb"],
    ["PHP heredoc", `$c = <<<EOT\n{password: ${C}}\nEOT;`, "app.php"],
    ["Java text block", `String c = """\n{password: ${C}}\n""";`, "App.java"],
    ["C# verbatim string", `var c = @"\n{password: ${C}}\n";`, "App.cs"],
    ["Rust raw string", `let c = r#"\n{password: ${C}}\n"#;`, "main.rs"],
    ["unterminated template (confused)", `const y = \`x\n{password: ${C}}`, "a.ts"],
    ["unterminated block comment (confused)", `const a = 1; /* x\n{password: ${C}}`, "a.ts"],
  ])("detects %s: multi-line strings are tracked over the file (#145)", (_label, text, path) => {
    expectCredential(text, path);
  });

  // #142 false positives must stay fixed with the whole-file string tracking (#145).
  it.each([
    ["after a closed template", "const t = `x`;\nconst x = { password: passwordFromVault };"],
    [
      "after a nested template",
      'const t = `a${b ? `c` : "d"}e`;\nconst x = { password: passwordFromVault };',
    ],
    ["after a comment with an apostrophe", "// don't\nconst x = { password: passwordFromVault };"],
    ["after a block comment", "/* it's */\nconst x = { password: passwordFromVault };"],
    ["after a division", 'const r = a / b; const s = "/";\nconst x = { secret: ACCESS_TOKEN };'],
    ["after a regex with a quote", "const re = /'/;\nconst x = { password: passwordFromVault };"],
  ])("ignores code %s (#145)", (_label, text) => {
    expect(detectSecrets(text, { path: "src/module.ts" })).toEqual([]);
  });

  it.each([
    ["Python after a closed block", 'x = """doc"""\nconnect(password=userSuppliedValue)', "a.py"],
    ["Python after a comment", "# it's\nconnect(password=userSuppliedValue)", "a.py"],
    ["Ruby after a heredoc", "a = <<~EOS\n  x\nEOS\nconnect(password: passwordFromVault)", "a.rb"],
  ])("ignores %s (#145)", (_label, text, path) => {
    expect(detectSecrets(text, { path })).toEqual([]);
  });

  it.each([
    ["template literal value", `const password = \`${L}\`;`, "src/db.ts"],
    ["Go short declaration", `password := "${L}"`, "main.go"],
    ["index assignment", `headers["x-api-key"] = "${L}";`, "src/client.ts"],
  ])("detects a %s (#145)", (_label, text, path) => {
    expectCredential(text, path);
  });

  it.each([
    ["a Go short declaration of a variable", "secret := mySecretValue"],
    ["a Go call", "token := getTokenFromVault(ctx)"],
    ["an index assignment of a variable", 'headers["x-api-key"] = apiKeyFromVault;'],
    ["a ternary between key names in backticks", "const label = cond ? `apiKey` : `clientSecret`;"],
  ])("ignores %s (#145)", (_label, text) => {
    expect(detectSecrets(text, { path: "src/module.ts" })).toEqual([]);
    expect(detectSecrets(text, { path: "internal/scan/module.go" })).toEqual([]);
  });

  it.each([
    ["TS typed declaration", `const dbPassword: string = "${L}";`, "src/db.ts"],
    ["optional typed class field", `private readonly apiKey?: string = "${L}";`, "src/db.ts"],
    ["Python typed assignment", `password: str = "${L}"`, "app/db.py"],
    ["Go typed var", `var password string = "${L}"`, "main.go"],
    ["quoted secret in a ternary", `const accessKey = cond ? "${L}" : "other";`, "src/db.ts"],
    ["quoted fallback after ??", `const apiKey = process.env.API_KEY ?? "${L}";`, "src/db.ts"],
    ["quoted fallback after ||", `const apiKey = process.env.API_KEY || "${L}";`, "src/db.ts"],
  ])("detects a %s (#145)", (_label, text, path) => {
    expectCredential(text, path);
  });

  it.each([
    ["a typed field set to a variable", "class A { secret: string = defaultSecretValue }"],
    ["a comparison", 'if (password == "Xq9vL2mTz8RkWp4N") {}'],
    ["a typed parameter with a constant default", "function f(password: string = DEFAULT_PW) {}"],
  ])("ignores %s (#145)", (_label, text) => {
    expect(detectSecrets(text, { path: "src/module.ts" })).toEqual([]);
  });

  it.each([
    ["unquoted YAML value with (", "password: K9x(mQ2vLp8Wz4Rt", "config/app.yml"],
    ["unquoted YAML value ending in (", "password: K9xmQ2vLp8Wz4Rt(", "config/app.yml"],
    ["quoted value with (", 'const password = "K9x(mQ2vLp8Wz4Rt";', "src/db.ts"],
    ["value with ( in a multi-line string", 'CFG = """\npassword=K9x(mQ2vLp8Wz4Rt\n"""', "a.py"],
  ])("detects a %s (#145)", (_label, text, path) => {
    expectCredential(text, path);
  });

  it.each([
    ["a call with arguments", 'const apiKey = getApiKey(config, "default")', "src/a.ts"],
    ["a Python call with arguments", "password = hash_password(user_input, salt)", "a.py"],
    ["a complete call in a config file", "password: getSecret()", "config/app.yml"],
  ])("ignores %s (#145)", (_label, text, path) => {
    expect(detectSecrets(text, { path })).toEqual([]);
  });

  it.each([
    ["in a TS string", `const u = "postgres://admin:${L}@db.prod.internal:5432/app";`, "a.ts"],
    ["with an empty user", `url: redis://:${L}@cache:6379`, "config/app.yml"],
    ["in an env file", `DATABASE_URL=mysql://app:${C}@db/app`, ".env"],
  ])("detects a password in a URL %s, keeping only the password (#145)", (_label, text, path) => {
    const found = detectSecrets(text, { path }).find((secret) => secret.kind === "url_credential");
    expect(found?.value).toMatch(/^(?:Qw|K9)/);
    expect(found?.value).not.toContain("@");
    expect(found?.value).not.toContain("admin");
  });

  it.each([
    ["placeholder words", 'const u = "postgres://user:password@localhost/db";'],
    ["an interpolated password", 'const u = "postgres://user:${DB_PASSWORD}@localhost/db";'],
    ["a port and a mail address", 'const u = "https://host:8080/path?x=a@b";'],
    ["a user without a password", 'const u = "https://token@github.com/org/repo";'],
  ])("ignores URLs with %s (#145)", (_label, text) => {
    expect(detectSecrets(text, { path: "src/db.ts" })).toEqual([]);
  });

  it("stays linear on large inputs (#145)", () => {
    const shapes = [
      'const x = { password: passwordFromVault, label: "it\'s" }; // don\'t\nconst re = /"/;\n',
      "password secret apiKey accessToken ",
      "password=x(/[",
      "postgres://user:pa@x ",
      `${"a".repeat(39)}password_${"b".repeat(39)} `,
      "password: abc <<~A r#\"`${'",
    ];
    const time = (text: string) => {
      const start = performance.now();
      for (const path of ["big.ts", "big.rb", "config.yml"]) detectSecrets(text, { path });
      return performance.now() - start;
    };
    for (const shape of shapes) {
      // Starts with an unquoted match so the string tracker runs over the whole text.
      const unit = `x = { password: passwordFromVault };\n${shape.repeat(Math.ceil(1_250_000 / shape.length))}`;
      time(unit.slice(0, 100_000)); // warm up
      const small = time(unit);
      const large = time(unit.repeat(4)); // 5 MB
      // 4x the input should take roughly 4x the time (16x if quadratic). CI runners are much
      // slower than local machines, so the absolute bound is loose.
      expect(large / Math.max(small, 1)).toBeLessThan(10);
      expect(large).toBeLessThan(15_000);
    }
  }, 120_000);

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

  it("reports #145 credentials as PG-SECRET-002 without their values", async () => {
    fixture = createGitFixture();
    const password = join("Qw9", "ErTy", "UiOp", "AsDf");
    const bracketed = join("K9x", "[mQ2]", "vLp8", "Wz4Rt");
    fixture.commit({
      files: {
        "src/db.ts": [
          `const url = "postgres://admin:${password}@db.internal:5432/app";`,
          `const dbPassword: string = "${password}x";`,
          `const y = \`\n{password: ${bracketed}, user: a}\n\`;`,
        ].join("\n"),
        "main.go": `package main\n\nfunc f() {\n\tpassword := "${password}y"\n}\n`,
      },
    });
    const result = await scanGitHistory(fixture.root);
    const tracked = byRule(result, "PG-SECRET-002");
    expect(tracked.map((finding) => [finding.location.path, finding.location.line])).toEqual(
      expect.arrayContaining([
        ["src/db.ts", 1],
        ["src/db.ts", 2],
        ["src/db.ts", 4],
        ["main.go", 4],
      ]),
    );
    expect(tracked.find((finding) => finding.location.line === 1)).toMatchObject({
      evidence: "password in a URL in a tracked file (value redacted)",
      status: "suspected",
    });
    const json = JSON.stringify(result);
    expect(json).not.toContain(password);
    expect(json).not.toContain(bracketed);
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
    // A first-party NestJS module named vendor is never suggested for removal.
    fixture.commit({
      files: {
        "package.json": '{ "name": "api" }\n',
        "src/vendor/vendor.module.ts": "export class VendorModule {}\n",
        "src/vendor/vendor.service.ts": "export class VendorService {}\n",
      },
    });
    expect(byRule(await scanGitHistory(fixture.root), "PG-HYGIENE-001")).toEqual([]);
  });

  it("emits PG-HYGIENE-001 for a root vendor/ next to composer.json", async () => {
    fixture = createGitFixture();
    fixture.commit({
      files: {
        "composer.json": '{ "require": { "guzzlehttp/guzzle": "^7.0" } }\n',
        "vendor/autoload.php": "<?php\n",
        "vendor/guzzlehttp/guzzle/src/Client.php": "<?php\n",
        "src/vendor/Mine.php": "<?php\n",
      },
    });
    const hygiene = byRule(await scanGitHistory(fixture.root), "PG-HYGIENE-001");
    expect(hygiene).toHaveLength(1);
    expect(hygiene[0]?.location.path).toBe("vendor/");
    expect(hygiene[0]?.evidence).toMatch(/: vendor\/ \(2 tracked files\)$/);
    expect(hygiene[0]?.recommendation).toContain("git rm -r --cached vendor)");
  });
});
