import { createRequire } from "node:module";
import path from "node:path";
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
};

export type ManifestKind = "maven" | "gradle" | "python-requirements" | "pyproject" | "composer";

/** Classifies a file name as a dependency manifest used for framework detection. */
export function classifyManifest(fileName: string): ManifestKind | null {
  if (fileName === "pom.xml") return "maven";
  if (fileName === "build.gradle" || fileName === "build.gradle.kts") return "gradle";
  if (/^requirements([-_.][\w.-]*)?\.txt$/.test(fileName)) return "python-requirements";
  if (fileName === "pyproject.toml") return "pyproject";
  if (fileName === "composer.json") return "composer";
  return null;
}

const require = createRequire(import.meta.url);

/**
 * Absolute path of a grammar `.wasm` file. Java, Python and PHP come from the
 * `@vscode/tree-sitter-wasm` dependency; Kotlin is vendored in `grammars/` (see its README).
 * `src/tree-sitter` and `dist/tree-sitter` are the same depth, so the vendored path holds for both.
 */
export function grammarPath(language: TreeSitterLanguage): string {
  if (language === "kotlin") {
    return fileURLToPath(new URL("../../grammars/tree-sitter-kotlin.wasm", import.meta.url));
  }
  const packageRoot = path.dirname(require.resolve("@vscode/tree-sitter-wasm/package.json"));
  return path.join(packageRoot, "wasm", `tree-sitter-${language}.wasm`);
}
