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
});
