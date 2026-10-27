import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Languages parsed with tree-sitter (WASM). JS/TS, Vue and Go keep their own analyzers. */
export type TreeSitterLanguage = "java" | "kotlin" | "python" | "php";

export const TREE_SITTER_LANGUAGES: readonly TreeSitterLanguage[] = [
  "java",
  "kotlin",
  "python",
  "php",
];

export const TREE_SITTER_LANGUAGE_LABEL: Record<TreeSitterLanguage, string> = {
  java: "Java",
  kotlin: "Kotlin",
  python: "Python",
  php: "PHP",
};

/** File extension (with dot) to language. `.kts` is deliberately absent (Gradle scripts). */
export const TREE_SITTER_EXTENSIONS: Record<string, TreeSitterLanguage | undefined> = {
  ".java": "java",
  ".kt": "kotlin",
  ".py": "python",
  ".php": "php",
  ".phtml": "php",
};

export type ManifestKind =
  | "maven"
  | "gradle"
  | "gradle-catalog"
  | "python-requirements"
  | "pyproject"
  | "python-setup"
  | "pipfile"
  | "composer";

/** Classifies a file name as a dependency manifest used for framework detection. */
export function classifyManifest(fileName: string, parentName = ""): ManifestKind | null {
  if (fileName === "pom.xml") return "maven";
  if (fileName === "build.gradle" || fileName === "build.gradle.kts") return "gradle";
  if (/^requirements([-_.][\w.-]*)?\.txt$/.test(fileName)) return "python-requirements";
  if (parentName === "requirements" && /^[\w.-]+\.txt$/.test(fileName))
    return "python-requirements";
  if (fileName === "libs.versions.toml") return "gradle-catalog";
  if (fileName === "pyproject.toml") return "pyproject";
  if (fileName === "setup.py" || fileName === "setup.cfg") return "python-setup";
  if (fileName === "Pipfile") return "pipfile";
  if (fileName === "composer.json") return "composer";
  return null;
}

/**
 * Pinned SHA-256 of every vendored grammar: the single source of truth. The runtime checks it
 * before a grammar is loaded, and a test keeps `grammars/README.md` and the files in agreement.
 * To update a grammar, replace the file and change the checksum here and in the README.
 */
export const GRAMMAR_SHA256: Readonly<Record<TreeSitterLanguage, string>> = {
  java: "4fdeac4ca6ca089f06c6f7e562abcac1733cd465728cc7031ebb73c2019122c4",
  kotlin: "7009d69453bc8735e438b2818a633efb21c88f99782769abba60dffedfab73f7",
  python: "16108b50df4ee9a30168794252ab55e7c93bfc5765d7fa0aa3e335752c515f47",
  php: "d4df6a6ff08c87c3ec4f9cbb785fe09998a0cb570e03f57d7b19b3acfb146aa7",
};

export type GrammarLoad = { ok: true; bytes: Uint8Array } | { ok: false; reason: string };

/**
 * Reads a grammar and verifies its pinned SHA-256. The returned bytes are the verified ones, so
 * the caller loads exactly what was checked. Never throws; the reason names the file, never a
 * path (Node's own messages contain paths).
 */
export function readVerifiedGrammar(
  language: TreeSitterLanguage,
  filePath: string = grammarPath(language),
): GrammarLoad {
  const name = `tree-sitter-${language}.wasm`;
  let data: Buffer;
  try {
    data = readFileSync(filePath);
  } catch (error) {
    return {
      ok: false,
      reason: `${name} is unreadable (${(error as NodeJS.ErrnoException).code ?? "unknown error"})`,
    };
  }
  if (createHash("sha256").update(data).digest("hex") !== GRAMMAR_SHA256[language]) {
    return { ok: false, reason: `${name} does not match its pinned SHA-256 checksum` };
  }
  return { ok: true, bytes: data };
}

/**
 * Absolute path of a vendored grammar `.wasm` file in `grammars/` (see its README for sources and
 * checksums). `src/tree-sitter` and `dist/tree-sitter` are the same depth, so the path resolves
 * for both; the `grammars/` directory must stay next to `src` and `dist` when packaged.
 */
export function grammarPath(language: TreeSitterLanguage): string {
  return fileURLToPath(new URL(`../../grammars/tree-sitter-${language}.wasm`, import.meta.url));
}
