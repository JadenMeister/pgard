import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listParseFixtures, readFixture } from "../test-support/fixtures.js";
import { walkSourceTree } from "../walk.js";
import { detectLanguageTrack, parseCoverage, parseTrackFiles } from "./language-track.js";
import { TREE_SITTER_LANGUAGES, type TreeSitterLanguage } from "./languages.js";
import { TreeSitterRuntime } from "./runtime.js";

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-ts-")));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    writeFileSync(path.join(root, name), content);
  }
  return root;
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const ROOT_TYPES: Record<TreeSitterLanguage, string> = {
  java: "program",
  kotlin: "source_file",
  python: "module",
  php: "program",
};

describe("grammars", () => {
  const runtime = new TreeSitterRuntime();
  for (const language of TREE_SITTER_LANGUAGES) {
    it(`loads and parses the ${language} fixture`, async () => {
      const fixtures = listParseFixtures(language);
      expect(fixtures.length).toBeGreaterThan(0);
      for (const fixture of fixtures) {
        const outcome = await runtime.parse(language, readFixture(fixture));
        expect(outcome.status).toBe("parsed");
        if (outcome.status !== "parsed") continue;
        expect(outcome.tree.rootNode.type).toBe(ROOT_TYPES[language]);
        expect(outcome.errorCount).toBe(0);
        outcome.dispose();
      }
      expect(runtime.loadedLanguages()).toContain(language);
    });
  }
});

describe("lazy loading", () => {
  it("starts nothing before the first parse", () => {
    const runtime = new TreeSitterRuntime();
    expect(runtime.isStarted()).toBe(false);
    expect(runtime.loadedLanguages()).toEqual([]);
  });

  it("loads only the grammar of a language that has files", async () => {
    const root = project({ "a/Main.java": "class Main {}\n", "README.md": "x" });
    const walk = await walkSourceTree(root);
    const runtime = new TreeSitterRuntime();
    for (const language of TREE_SITTER_LANGUAGES) {
      await parseTrackFiles(runtime, language, walk.trackFiles[language]);
    }
    expect(runtime.loadedLanguages()).toEqual(["java"]);
  });

  it("loads nothing for a project without those languages", async () => {
    const root = project({ "index.ts": "export const a = 1;\n", "main.go": "package main\n" });
    const walk = await walkSourceTree(root);
    const runtime = new TreeSitterRuntime();
    for (const language of TREE_SITTER_LANGUAGES) {
      await parseTrackFiles(runtime, language, walk.trackFiles[language]);
    }
    expect(runtime.isStarted()).toBe(false);
    expect(runtime.loadedLanguages()).toEqual([]);
    expect((await detectLanguageTrack(walk)).languages).toEqual([]);
  });
});

describe("limits", () => {
  it("does not parse a source over the size limit", async () => {
    const runtime = new TreeSitterRuntime();
    const outcome = await runtime.parse("python", "x = 1\n".repeat(100), { maxBytes: 50 });
    expect(outcome).toMatchObject({ status: "too_large", maxBytes: 50 });
    expect(runtime.isStarted()).toBe(false);
  });

  it("cancels a parse that exceeds the time budget", async () => {
    const runtime = new TreeSitterRuntime();
    let tick = 0;
    const outcome = await runtime.parse("java", "class A { int a; }\n".repeat(50_000), {
      timeoutMs: 10,
      now: () => (tick += 5),
    });
    expect(outcome).toMatchObject({ status: "timeout", timeoutMs: 10 });
    const again = await runtime.parse("java", "class B {}\n");
    expect(again.status).toBe("parsed");
    if (again.status === "parsed") again.dispose();
  });

  it("makes coverage partial for oversized and timed-out files, never completed", async () => {
    const root = project({ "big.py": "x = 1\n".repeat(200), "ok.py": "x = 1\n" });
    const walk = await walkSourceTree(root);
    const runtime = new TreeSitterRuntime();
    const limits = { maxBytes: 100 };
    const stats = await parseTrackFiles(runtime, "python", walk.trackFiles.python, limits);
    expect(stats.tooLarge).toEqual(["big.py"]);
    expect(stats.parsed).toBe(1);
    const coverage = parseCoverage("python", ["PG-X"], stats, limits);
    expect(coverage.status).toBe("partial");
    expect(coverage.note).toContain("not a safe result");
    expect(coverage.note).toContain("big.py");

    const timedOut = { ...stats, tooLarge: [], timedOut: ["slow.py"] };
    const timeoutCoverage = parseCoverage("python", [], timedOut, { timeoutMs: 5 });
    expect(timeoutCoverage.status).toBe("partial");
    expect(timeoutCoverage.note).toContain("scan deadline");
  });

  it("tolerates syntax errors but counts them", async () => {
    const runtime = new TreeSitterRuntime();
    const outcome = await runtime.parse("java", "class A { void f( { int = ; }\n");
    expect(outcome.status).toBe("parsed");
    if (outcome.status !== "parsed") return;
    expect(outcome.errorCount + outcome.missingCount).toBeGreaterThan(0);
    outcome.dispose();

    const root = project({ "Bad.java": "class A { void f( { int = ; }\n" });
    const walk = await walkSourceTree(root);
    const stats = await parseTrackFiles(runtime, "java", walk.trackFiles.java);
    expect(stats.parsed).toBe(1);
    expect(stats.filesWithSyntaxErrors).toBe(1);
    const coverage = parseCoverage("java", [], stats);
    expect(coverage.status).toBe("completed");
    expect(coverage.note).toContain("syntax errors");
  });
});
