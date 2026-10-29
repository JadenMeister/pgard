import { writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { isTextLike, readStagedChanges } from "./staged.js";
import { readStagedTextFile } from "./staged-file.js";
import { scanStagedPaths, scanStagedSecrets } from "./staged-secrets.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

vi.setConfig({ testTimeout: 30_000 });

// Assembled at run time so this file holds no literal token.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;

function pem(body: string[]): string {
  return `-----BEGIN RSA PRIVATE KEY-----\n${body.join("\n")}\n-----END RSA PRIVATE KEY-----\n`;
}
const LINE_A = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";
const LINE_B = "VTQsA9b8w2Qe3K1m5bPzLq0cYpD7uWvXnR4tHjEiOaFgBs8dZkCyJlM6xN2UhG9r";
const LINE_C = "qT5wYeA3oPvIfSbDcLnK0zXmJuR7gHtB1yEhQaWiVd4CxNs8ZkO6lMpFjU2rGb9T";

describe("a changed key body is not hidden by an unchanged header", () => {
  const file = (content: string, previous: string | null) => ({
    path: "keys/server.pem",
    content,
    previous,
    kind: "modified" as const,
  });

  it("reports the same PEM file with a different key body", () => {
    const before = pem([LINE_A, LINE_B, LINE_C]);
    const after = pem([LINE_C, LINE_B, LINE_A.replace("u1SU", "Z9QW")]);
    const result = scanStagedSecrets([file(after, before)]);
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-002"]);
    expect(result.preexisting).toBe(0);
  });

  it("reports a change to one middle line of the key (the match spans many lines)", () => {
    const before = pem([LINE_A, LINE_B, LINE_C]);
    const after = pem([LINE_A, LINE_B.replace("VTQs", "XXQs"), LINE_C]);
    expect(scanStagedSecrets([file(after, before)]).findings).toHaveLength(1);
  });

  it("reports a copy of an existing secret on a new line", () => {
    const old = `token = "${GITHUB_TOKEN}"\n`;
    const result = scanStagedSecrets([file(`${old}other = "${GITHUB_TOKEN}"\n`, old)]);
    expect(result.findings).toHaveLength(1);
  });

  it("does not report a key the commit leaves untouched", () => {
    const before = pem([LINE_A, LINE_B, LINE_C]);
    const result = scanStagedSecrets([file(`# note\n${before}`, before)]);
    expect(result.findings).toEqual([]);
    expect(result.preexisting).toBe(1);
  });
});

describe("a NUL byte hides nothing", () => {
  const fixtures: GitFixture[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) fixture.cleanup();
  });
  const repo = () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files: { "README.md": "x\n" } });
    return fixture;
  };

  it("tells text with a stray NUL from binary data", () => {
    expect(isTextLike("KEY=value\n\0")).toBe(true);
    expect(isTextLike(`x = "${GITHUB_TOKEN}"\0`)).toBe(true);
    expect(isTextLike("\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x01\0\0\0\x01\0\x08\x02\0\0\0")).toBe(
      false,
    );
    expect(isTextLike(`${"\0".repeat(100)}text`)).toBe(false);
  });

  it("scans a .env file and a config.js with a trailing NUL", async () => {
    const fixture = repo();
    writeFileSync(path.join(fixture.root, ".env"), "API_KEY=abc\n\0");
    writeFileSync(path.join(fixture.root, "config.js"), `const t = "${GITHUB_TOKEN}";\n\0`);
    fixture.git("add", ".env", "config.js");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped).toEqual([]);
    expect(changes.files.map((file) => file.path)).toEqual([".env", "config.js"]);
    const result = scanStagedSecrets(changes.files);
    expect(result.findings.map((finding) => [finding.ruleId, finding.location.path])).toEqual([
      ["PG-SECRET-001", ".env"],
      ["PG-SECRET-002", "config.js"],
    ]);
    // NUL becomes a space: line numbers stay exact.
    expect(changes.files[1]?.content).toContain(`"${GITHUB_TOKEN}";`);
  });

  it("flags a new .env file by its name even when it is binary or too large", async () => {
    const fixture = repo();
    writeFileSync(
      path.join(fixture.root, "prod.env"),
      Buffer.from(Array.from({ length: 300 }, (_, i) => (i % 3 === 0 ? 0 : (i * 7) % 256))),
    );
    writeFileSync(path.join(fixture.root, "big.env"), "A=1\n".repeat(400_000));
    fixture.git("add", "prod.env", "big.env");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped.map((item) => [item.path, item.reason, item.kind])).toEqual(
      [
        ["prod.env", "binary", "added"],
        ["big.env", "too_large", "added"],
      ].sort((a, b) => (a[0] as string).localeCompare(b[0] as string)),
    );
    expect(
      scanStagedPaths(changes.skipped)
        .map((item) => item.location.path)
        .sort(),
    ).toEqual(["big.env", "prod.env"]);
  });

  it("does not flag a modified .env by name (its content is still scanned)", () => {
    expect(scanStagedPaths([{ path: ".env", reason: "too_large", kind: "modified" }])).toEqual([]);
  });
});

describe("large files", () => {
  const fixtures: GitFixture[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) fixture.cleanup();
  });

  it("calls a big binary a binary, and a big text file too large", async () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files: { "README.md": "x\n" } });
    const binary = Buffer.alloc(2 * 1024 * 1024);
    for (let index = 0; index < binary.length; index += 1) binary[index] = index % 251;
    writeFileSync(path.join(fixture.root, "photo.png"), binary);
    writeFileSync(
      path.join(fixture.root, "package-lock.json"),
      `{"a":"${"x".repeat(2 * 1024 * 1024)}"}\n`,
    );
    fixture.git("add", "photo.png", "package-lock.json");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped.map((item) => [item.path, item.reason])).toEqual([
      ["package-lock.json", "too_large"],
      ["photo.png", "binary"],
    ]);
  });
});

describe("readStagedTextFile", () => {
  const fixtures: GitFixture[] = [];
  afterEach(() => {
    for (const fixture of fixtures.splice(0)) fixture.cleanup();
  });

  it("reads the staged version, not the working tree, and not an untracked file", async () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files: { "README.md": "x\n" } });
    expect(await readStagedTextFile(fixture.root, "pgard.config.json")).toEqual({
      state: "absent",
    });
    fixture.writeFile("pgard.config.json", '{"version":1}\n');
    expect(await readStagedTextFile(fixture.root, "pgard.config.json")).toEqual({
      state: "absent",
    });
    fixture.git("add", "pgard.config.json");
    fixture.writeFile("pgard.config.json", '{"version":2}\n');
    expect(await readStagedTextFile(fixture.root, "pgard.config.json")).toEqual({
      state: "ok",
      text: '{"version":1}\n',
    });
  });

  it("refuses a file that is too large or not UTF-8", async () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files: { "README.md": "x\n" } });
    fixture.writeFile("pgard.config.json", "x".repeat(70_000));
    fixture.git("add", "pgard.config.json");
    expect(await readStagedTextFile(fixture.root, "pgard.config.json")).toMatchObject({
      state: "unreadable",
    });
    writeFileSync(
      path.join(fixture.root, "pgard.config.json"),
      Buffer.from([0xff, 0xfe, 0xfd, 0x80]),
    );
    fixture.git("add", "pgard.config.json");
    expect(await readStagedTextFile(fixture.root, "pgard.config.json")).toMatchObject({
      state: "unreadable",
      reason: "it is not valid UTF-8 text",
    });
  });
});
