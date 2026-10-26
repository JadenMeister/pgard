import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseCoverage, parseTrackFiles } from "./language-track.js";
import {
  GRAMMAR_SHA256,
  grammarPath,
  readVerifiedGrammar,
  TREE_SITTER_LANGUAGES,
} from "./languages.js";
import { TreeSitterRuntime } from "./runtime.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** A copy of the Python grammar with one byte flipped. */
function flippedPython(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "pgard-grammar-"));
  dirs.push(dir);
  const file = path.join(dir, "tree-sitter-python.wasm");
  const bytes = readFileSync(grammarPath("python"));
  const index = Math.floor(bytes.length / 2);
  bytes[index] = (bytes[index] ?? 0) ^ 0xff;
  writeFileSync(file, bytes);
  return file;
}

describe("grammar checksums", () => {
  it("pins every language and matches the grammars README", () => {
    const readme = readFileSync(new URL("../../grammars/README.md", import.meta.url), "utf8");
    for (const language of TREE_SITTER_LANGUAGES) {
      expect(readme).toContain(`\`tree-sitter-${language}.wasm\``);
      expect(readme).toContain(`\`${GRAMMAR_SHA256[language]}\``);
    }
  });

  it("accepts every vendored grammar", () => {
    for (const language of TREE_SITTER_LANGUAGES) {
      expect(readVerifiedGrammar(language).ok).toBe(true);
    }
  });

  it("rejects a byte-flipped grammar with a reason that holds no path", () => {
    const result = readVerifiedGrammar("python", flippedPython());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(
        "tree-sitter-python.wasm does not match its pinned SHA-256 checksum",
      );
    }
  });

  it("rejects a missing grammar without throwing", () => {
    const result = readVerifiedGrammar("python", path.join(tmpdir(), "pgard-no-such.wasm"));
    expect(result).toEqual({ ok: false, reason: "tree-sitter-python.wasm is unreadable (ENOENT)" });
  });

  it("never parses with a byte-flipped grammar and reports not_tested", async () => {
    const bad = flippedPython();
    const runtime = new TreeSitterRuntime(() => bad);
    const outcome = await runtime.parse("python", "def f():\n    return 1\n");
    expect(outcome.status).toBe("unavailable");
    expect(runtime.loadedLanguages()).toEqual([]);

    const dir = mkdtempSync(path.join(tmpdir(), "pgard-grammar-src-"));
    dirs.push(dir);
    const files = ["a.py", "b.py"].map((name) => {
      writeFileSync(path.join(dir, name), "x = 1\n");
      return { absolutePath: path.join(dir, name), relativePath: name, size: 6 };
    });
    const stats = await parseTrackFiles(new TreeSitterRuntime(() => bad), "python", files);
    expect(stats.parsed).toBe(0);
    expect(stats.files).toBe(2);
    const coverage = parseCoverage("python", ["PG-X"], stats);
    expect(coverage.status).toBe("not_tested");
    expect(coverage.ruleIds).toEqual([]);
    expect(coverage.note).toContain("does not match its pinned SHA-256 checksum");
  });

  it("keeps the other languages working when one grammar is bad", async () => {
    const bad = flippedPython();
    const runtime = new TreeSitterRuntime((language) =>
      language === "python" ? bad : grammarPath(language),
    );
    expect((await runtime.parse("python", "x = 1\n")).status).toBe("unavailable");
    const java = await runtime.parse("java", "class A {}\n");
    expect(java.status).toBe("parsed");
    if (java.status === "parsed") java.dispose();
    copyFileSync(grammarPath("python"), bad);
    // A grammar that failed verification stays unavailable for this runtime instance.
    expect((await runtime.parse("python", "x = 1\n")).status).toBe("unavailable");
  });
});
