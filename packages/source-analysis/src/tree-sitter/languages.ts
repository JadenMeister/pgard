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
 * Absolute path of a vendored grammar `.wasm` file in `grammars/` (see its README for sources and
 * checksums). `src/tree-sitter` and `dist/tree-sitter` are the same depth, so the path resolves
 * for both; the `grammars/` directory must stay next to `src` and `dist` when packaged.
 */
export function grammarPath(language: TreeSitterLanguage): string {
  return fileURLToPath(new URL(`../../grammars/tree-sitter-${language}.wasm`, import.meta.url));
}
