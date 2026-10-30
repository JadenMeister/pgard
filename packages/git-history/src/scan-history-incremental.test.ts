import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@pgard/findings";
import { isAncestorCommit, listChangedPaths, scanGitHistory } from "./scan-history.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

const join = (...parts: string[]) => parts.join("");
const TOKEN = join("ghp", "_", "Zq8", "aB3cD4eF5g", "Lm4", "hJ6kL7mN8p", "Pw7", "qR9sT0uV1w");
const OTHER = join("ghp", "_", "R3mOv3dT0k3n", "AbCdEfGhIjKl", "MnOpQrStUvWxYz");

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

function baseOf(findings: readonly Finding[], baseRevision: string) {
  return {
    baseRevision,
    carried: findings.filter((f) => f.location.commit !== null),
    trackedFindingPaths: findings
      .filter((f) => f.location.commit === null && f.location.path !== null)
      .map((f) => f.location.path as string),
  };
}

const ids = (findings: readonly Finding[]) => findings.map((f) => f.id).sort();

describe("incremental history scan", () => {
  it("reads only the new commits and reports what a full scan reports", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "a.ts": `export const t = "${TOKEN}";\n`, "n.txt": "1" } });
    fixture.commit({ files: { "a.ts": "export const t = 1;\n" } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root);
    expect(first.history.mode).toBe("full");
    expect(first.findings.map((f) => f.ruleId)).toContain("PG-SECRET-003");

    fixture.commit({ files: { "n.txt": "2" } });
    fixture.commit({ files: { "m.txt": "3" } });
    const full = await scanGitHistory(fixture.root);
    const incremental = await scanGitHistory(fixture.root, {
      incremental: baseOf(first.findings, stored),
    });
    expect(incremental.history).toEqual({
      mode: "incremental",
      commitsScanned: 2,
      commitsReused: 2,
    });
    expect(ids(incremental.findings)).toEqual(ids(full.findings));
    expect(incremental.coverage.map((c) => [c.area, c.status])).toEqual(
      full.coverage.map((c) => [c.area, c.status]),
    );
  });

  it("scans in full when a new commit adds a secret and earlier history findings exist", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "a.ts": `export const t = "${TOKEN}";\n` } });
    fixture.commit({ files: { "a.ts": "export const t = 1;\n" } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root);
    fixture.commit({ files: { "b.ts": `export const t = "${TOKEN}";\n` } });
    const incremental = await scanGitHistory(fixture.root, {
      incremental: baseOf(first.findings, stored),
    });
    const full = await scanGitHistory(fixture.root);
    expect(incremental.history.mode).toBe("full");
    expect(ids(incremental.findings)).toEqual(ids(full.findings));
    // The old value is current again, so the earlier "no longer present" finding is gone.
    expect(incremental.findings.map((f) => f.ruleId)).not.toContain("PG-SECRET-003");
  });

  it("scans in full when a file that had a tracked-file finding changed", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "a.ts": `export const t = "${OTHER}";\n` } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root);
    expect(first.findings.map((f) => f.ruleId)).toEqual(["PG-SECRET-002"]);
    fixture.commit({ files: { "a.ts": "export const t = 1;\n" } });
    const incremental = await scanGitHistory(fixture.root, {
      incremental: baseOf(first.findings, stored),
    });
    expect(incremental.history.mode).toBe("full");
    expect(incremental.findings.map((f) => f.ruleId)).toEqual(["PG-SECRET-003"]);
  });

  it("scans in full when the stored commit is not an ancestor", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "a.txt": "1" } });
    fixture.commit({ files: { "a.txt": "2" } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root);
    fixture.git("reset", "-q", "--hard", "HEAD~1");
    fixture.commit({ files: { "a.txt": "other" } });
    const result = await scanGitHistory(fixture.root, {
      incremental: baseOf(first.findings, stored),
    });
    expect(result.history.mode).toBe("full");
  });

  it("tells ancestors from other commits and lists the paths that differ", async () => {
    fixture = createGitFixture();
    const one = fixture.commit({ files: { "a.txt": "1", "b.txt": "1" } });
    const two = fixture.commit({ files: { "a.txt": "2" }, remove: ["b.txt"] });
    expect(await isAncestorCommit(fixture.root, one, two)).toBe(true);
    expect(await isAncestorCommit(fixture.root, two, one)).toBe(false);
    expect(await isAncestorCommit(fixture.root, "0".repeat(40), two)).toBe(false);
    expect([...(await listChangedPaths(fixture.root, one, two))].sort()).toEqual([
      "a.txt",
      "b.txt",
    ]);
  });
});

describe("incremental history scan guards", () => {
  it("scans in full when a removed environment file is committed again", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { ".env": "KEY=1\n", "a.txt": "1" } });
    fixture.commit({ remove: [".env"], files: { "a.txt": "2" } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root);
    expect(first.findings.some((f) => f.ruleId === "PG-SECRET-001" && f.location.commit)).toBe(
      true,
    );
    fixture.commit({ files: { ".env": "KEY=2\n" } });
    const incremental = await scanGitHistory(fixture.root, {
      incremental: baseOf(first.findings, stored),
    });
    const full = await scanGitHistory(fixture.root);
    expect(incremental.history.mode).toBe("full");
    expect(ids(incremental.findings)).toEqual(ids(full.findings));
    expect(incremental.findings.some((f) => f.location.commit !== null)).toBe(false);
  });

  it("scans in full when a removed secret is committed again inside a binary file", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "a.ts": `export const t = "${TOKEN}";\n` } });
    fixture.commit({ files: { "a.ts": "export const t = 1;\n" } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root);
    expect(first.findings.map((f) => f.ruleId)).toContain("PG-SECRET-003");
    fixture.commit({ files: { "blob.bin": `\u0000\u0001${TOKEN}\u0000` } });
    const incremental = await scanGitHistory(fixture.root, {
      incremental: baseOf(first.findings, stored),
    });
    const full = await scanGitHistory(fixture.root);
    expect(incremental.history.mode).toBe("full");
    expect(ids(incremental.findings)).toEqual(ids(full.findings));
    expect(incremental.coverage.map((c) => [c.area, c.status])).toEqual(
      full.coverage.map((c) => [c.area, c.status]),
    );
  });

  it("scans in full when the history is longer than the commit window", async () => {
    fixture = createGitFixture();
    for (let index = 0; index < 4; index += 1) fixture.commit({ files: { "a.txt": `${index}` } });
    const stored = fixture.git("rev-parse", "HEAD").trim();
    const first = await scanGitHistory(fixture.root, { maxCommits: 3 });
    fixture.commit({ files: { "a.txt": "x" } });
    const incremental = await scanGitHistory(fixture.root, {
      maxCommits: 3,
      incremental: baseOf(first.findings, stored),
    });
    expect(incremental.history.mode).toBe("full");
    expect(incremental.coverage.find((c) => c.area === "history:commits")?.status).toBe("partial");
  });

  it("scans in full in a shallow clone", async () => {
    fixture = createGitFixture();
    for (let index = 0; index < 3; index += 1) fixture.commit({ files: { "a.txt": `${index}` } });
    const clone = mkdtempSync(path.join(tmpdir(), "pgard-shallow-"));
    try {
      execFileSync("git", ["clone", "-q", "--depth", "1", `file://${fixture.root}`, clone], {
        env: { PATH: process.env.PATH ?? "", HOME: clone, GIT_CONFIG_NOSYSTEM: "1" },
        timeout: 60_000,
        killSignal: "SIGKILL",
      });
      const stored = execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: clone,
        encoding: "utf8",
        timeout: 60_000,
        killSignal: "SIGKILL",
      }).trim();
      const incremental = await scanGitHistory(clone, {
        incremental: { baseRevision: stored, carried: [], trackedFindingPaths: [] },
      });
      expect(incremental.history.mode).toBe("full");
    } finally {
      rmSync(clone, { recursive: true, force: true });
    }
  });
});
