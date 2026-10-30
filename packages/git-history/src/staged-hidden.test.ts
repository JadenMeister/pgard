import { writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  hasBinarySignature,
  isClearlyBinary,
  looksBinaryContent,
  utf16WithoutMark,
} from "./binary-sniff.js";
import { decodeStagedBlob, decodeStagedBlobBoth, readStagedChanges } from "./staged.js";
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
    expect(isClearlyBinary("KEY=value\n\0")).toBe(false);
    expect(isClearlyBinary(`x = "${GITHUB_TOKEN}"\0`)).toBe(false);
    expect(isClearlyBinary("\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x01\0\0\0\x01\0\x08\x02\0\0\0")).toBe(
      true,
    );
    // Many NULs at the start but plain text at the end: not clearly binary.
    expect(isClearlyBinary(`${"\0".repeat(2000)}${"plain text ".repeat(3000)}`)).toBe(false);
    expect(isClearlyBinary(`${"\0".repeat(300)}${"\x01".repeat(300)}`)).toBe(true);
    expect(looksBinaryContent("")).toBe(false);
  });

  it("recognises well-known binary signatures", () => {
    for (const head of [
      "\xff\xd8\xff\xe0",
      "GIF89a\x01\0",
      "%PDF-1.7",
      "PK\x03\x04",
      "\x1f\x8b\x08",
      "\x7fELF\x02",
      "\xcf\xfa\xed\xfe",
      "\xca\xfe\xba\xbe",
      "wOF2OTTO",
      "RIFF\x24\0\0\0WEBPVP8 ",
      "\0\0\0\x18ftypmp42",
    ]) {
      expect(hasBinarySignature(head), JSON.stringify(head)).toBe(true);
      // With Git's own mark of a binary (a NUL in the first 8000 bytes) it is clearly binary.
      expect(isClearlyBinary(`${head}\0\0\0\0`), JSON.stringify(head)).toBe(true);
    }
    for (const text of ["ID3_TOKEN=1\n", "GIF is a format\n", "BZhello", "MZ is a prefix\n"]) {
      expect(isClearlyBinary(text), text).toBe(false);
    }
  });

  it("does not call a text file binary because it starts with a format signature", async () => {
    const text = `%PDF-1.4\nconst token = "${GITHUB_TOKEN}";\n`;
    expect(isClearlyBinary(text)).toBe(false);
    expect(decodeStagedBlob(text)).toBe(text);
    // Small: scanned. Large (1.3 MB of text after the signature): too large, never "binary".
    const fixture = repo();
    writeFileSync(path.join(fixture.root, "small.txt"), text);
    writeFileSync(
      path.join(fixture.root, "large.txt"),
      `%PDF-1.4\n${"ordinary text line\n".repeat(70_000)}const token = "${GITHUB_TOKEN}";\n`,
    );
    fixture.git("add", "small.txt", "large.txt");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.files.map((file) => file.path)).toEqual(["small.txt"]);
    expect(scanStagedSecrets(changes.files).findings).toHaveLength(1);
    expect(changes.skipped.map((item) => [item.path, item.reason])).toEqual([
      ["large.txt", "too_large"],
    ]);
  });

  it("reads a file that is UTF-16 at the start and UTF-8 later both ways", () => {
    const wide = Buffer.from("hello world\n".repeat(700), "utf16le").toString("latin1");
    const body = `${wide}const token = "${GITHUB_TOKEN}";\n`;
    const both = decodeStagedBlobBoth(body);
    expect(both.text).not.toContain(GITHUB_TOKEN);
    expect(both.alternate).toContain(GITHUB_TOKEN);
    const found = scanStagedSecrets([
      {
        path: "notes.txt",
        content: both.text ?? "",
        previous: null,
        kind: "added",
        ...(both.alternate === null ? {} : { alternate: both.alternate }),
      },
    ]);
    expect(found.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-002"]);
  });

  it("reports a secret that both readings see once", () => {
    const text = `token = "${GITHUB_TOKEN}"\n`;
    const both = decodeStagedBlobBoth(Buffer.from(text, "utf16le").toString("latin1"));
    const found = scanStagedSecrets([
      {
        path: "wide.txt",
        content: both.text ?? "",
        previous: null,
        kind: "added",
        ...(both.alternate === null ? {} : { alternate: both.alternate }),
      },
    ]);
    expect(found.findings).toHaveLength(1);
  });

  it("reports a new UTF-8 copy of a secret that already sat in the UTF-16 part", () => {
    const wide = `${"hello world\n".repeat(700)}token = "${GITHUB_TOKEN}"\n`;
    const before = Buffer.from(wide, "utf16le").toString("latin1");
    const after = `${before}copy = "${GITHUB_TOKEN}";\n`;
    const earlier = decodeStagedBlobBoth(before);
    const later = decodeStagedBlobBoth(after);
    const found = scanStagedSecrets([
      {
        path: "notes.txt",
        content: later.text ?? "",
        previous: earlier.text,
        kind: "modified",
        ...(later.alternate === null ? {} : { alternate: later.alternate }),
        ...(earlier.alternate === null ? {} : { previousAlternate: earlier.alternate }),
      },
    ]);
    expect(found.findings).toHaveLength(1);
    expect(found.preexisting).toBe(1);
  });

  it("decodes UTF-16 without a byte order mark and scans it", () => {
    const text = `token = "${GITHUB_TOKEN}"\n`;
    const le = Buffer.from(text, "utf16le").toString("latin1");
    const be = Buffer.from(Buffer.from(text, "utf16le").swap16()).toString("latin1");
    expect(utf16WithoutMark(le)).toBe("le");
    expect(utf16WithoutMark(be)).toBe("be");
    expect(utf16WithoutMark("plain ascii text without nul")).toBeNull();
    expect(decodeStagedBlob(le)).toBe(text);
    expect(decodeStagedBlob(be)).toBe(text);
    const found = scanStagedSecrets([
      { path: "config.txt", content: decodeStagedBlob(le) ?? "", previous: null, kind: "added" },
    ]);
    expect(found.findings.map((finding) => finding.ruleId)).toEqual(["PG-SECRET-002"]);
  });

  it("scans a staged UTF-16LE file without a mark end to end", async () => {
    const fixture = repo();
    writeFileSync(
      path.join(fixture.root, "wide.txt"),
      Buffer.from(`k = "${GITHUB_TOKEN}"\n`, "utf16le"),
    );
    fixture.git("add", "wide.txt");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped).toEqual([]);
    expect(scanStagedSecrets(changes.files).findings).toHaveLength(1);
  });

  it("scans a file with many NULs at the start and text with a secret after it", async () => {
    const fixture = repo();
    const head = `${"\0".repeat(2000)}${"a".repeat(6000)}`;
    writeFileSync(
      path.join(fixture.root, "mixed.dat"),
      `${head}\nkey = "${GITHUB_TOKEN}"\n${"padding\n".repeat(200)}`,
    );
    fixture.git("add", "mixed.dat");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped).toEqual([]);
    expect(scanStagedSecrets(changes.files).findings).toHaveLength(1);
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
        ["prod.env", "binary_suspected", "added"],
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
    Buffer.from("\x89PNG\r\n\x1a\n", "latin1").copy(binary);
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

  /** A file over 1 MiB that starts like a binary and goes on as text with a secret. */
  function mixedLargeFile(nulShare: number): Buffer {
    const head = Buffer.alloc(8000, "abcdefghij");
    for (let index = 0; index < head.length; index += 1) {
      if (index % Math.round(1 / nulShare) === 0) head[index] = 0;
    }
    const tail = `\nAWS_SECRET = "${"AKIA"}IOSFODNN7EXAMPLQ"\n${"ordinary text line\n".repeat(70_000)}`;
    return Buffer.concat([head, Buffer.from(tail)]);
  }

  it("keeps a big file that only starts with NULs as too large (not scanned), never as binary", async () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files: { "README.md": "x\n" } });
    // 5% NULs: over the old 2% threshold; 30% NULs: a binary-looking start.
    writeFileSync(path.join(fixture.root, "five.dat"), mixedLargeFile(0.05));
    writeFileSync(path.join(fixture.root, "thirty.dat"), mixedLargeFile(0.3));
    expect(mixedLargeFile(0.05).length).toBeGreaterThan(1024 * 1024);
    fixture.git("add", "five.dat", "thirty.dat");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped.map((item) => [item.path, item.reason])).toEqual([
      ["five.dat", "too_large"],
      ["thirty.dat", "too_large"],
    ]);
  });

  it("calls a big file binary by a signature, and one binary only by content not scanned", async () => {
    const fixture = createGitFixture();
    fixtures.push(fixture);
    fixture.commit({ files: { "README.md": "x\n" } });
    const png = Buffer.concat([
      Buffer.from("\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x01\0", "latin1"),
      Buffer.from(`AKIAIOSFODNN7EXAMPLQ ${"text ".repeat(300_000)}`),
    ]);
    const random = Buffer.alloc(2 * 1024 * 1024);
    for (let index = 0; index < random.length; index += 1)
      random[index] = (index * 2654435761) >>> 24;
    writeFileSync(path.join(fixture.root, "a.png"), png);
    writeFileSync(path.join(fixture.root, "blob.bin"), random);
    fixture.git("add", "a.png", "blob.bin");
    const changes = await readStagedChanges(fixture.root);
    expect(changes.skipped.map((item) => [item.path, item.reason])).toEqual([
      ["a.png", "binary"],
      ["blob.bin", "binary_suspected"],
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
