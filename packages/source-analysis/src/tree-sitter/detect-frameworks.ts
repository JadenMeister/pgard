import type { ManifestFile } from "../walk.js";
import { readTextFile } from "../walk.js";
import type { ManifestKind, TreeSitterLanguage } from "./languages.js";

/** Manifests larger than this are not read (a hostile or generated file must not cost memory). */
export const MAX_MANIFEST_BYTES = 1024 * 1024;
/** `requirements.txt` lines read; longer files are cut and reported. */
const MAX_REQUIREMENT_LINES = 20_000;

export type Framework = "Spring" | "Django" | "Flask" | "FastAPI" | "Laravel" | "Symfony";

/** Languages a framework's code is written in. Spring projects are Java or Kotlin. */
export const FRAMEWORK_LANGUAGES: Record<Framework, readonly TreeSitterLanguage[]> = {
  Spring: ["java", "kotlin"],
  Django: ["python"],
  Flask: ["python"],
  FastAPI: ["python"],
  Laravel: ["php"],
  Symfony: ["php"],
};

export interface DetectedFramework {
  framework: Framework;
  /** Repository-relative path of the manifest that named the framework. */
  manifestPath: string;
}

export type ManifestIssueReason = "unreadable_or_too_large" | "unsafe_xml" | "invalid_json" | "cut";

export interface ManifestIssue {
  path: string;
  reason: ManifestIssueReason;
}

export interface FrameworkDetection {
  frameworks: DetectedFramework[];
  /** Manifests that could not be fully used. Framework detection is weaker, never "safe". */
  issues: ManifestIssue[];
}

const PYTHON_FRAMEWORKS: Record<string, Framework> = {
  django: "Django",
  flask: "Flask",
  fastapi: "FastAPI",
};

/**
 * Removes `open ... close` sections in linear time. An unclosed section runs to the end of the
 * text (a regular expression would rescan the rest from every unclosed opener).
 */
function stripDelimited(text: string, open: string, close: string): string {
  let result = "";
  let position = 0;
  for (;;) {
    const start = text.indexOf(open, position);
    if (start === -1) return result + text.slice(position);
    result += text.slice(position, start);
    const end = text.indexOf(close, start + open.length);
    if (end === -1) return result;
    position = end + close.length;
  }
}

/** `-` and `_` are equivalent in Python package names (PEP 503); case is ignored. */
function normalizePythonName(name: string): string {
  return name.toLowerCase().replace(/[_.]+/g, "-");
}

/**
 * Maven: only `<groupId>` text is read, with regular expressions. The XML is never parsed by an
 * engine that could expand entities or fetch DTDs; a DOCTYPE or ENTITY declaration marks the file
 * as unsafe and nothing is extracted from it.
 */
export function detectMavenFrameworks(text: string): Framework[] | "unsafe_xml" {
  if (/<!(?:DOCTYPE|ENTITY)/i.test(text)) return "unsafe_xml";
  const withoutComments = stripDelimited(stripDelimited(text, "<!--", "-->"), "<![CDATA[", "]]>");
  for (const match of withoutComments.matchAll(/<groupId>\s*([^<\s]{1,200})\s*<\/groupId>/g)) {
    if (/^org\.springframework(?:\.|$)/.test(match[1] as string)) return ["Spring"];
  }
  return [];
}

/**
 * Removes line and block comments from a Gradle script in linear time, leaving string contents
 * alone (`"https://repo"` keeps its `//`). An unclosed block comment runs to the end.
 */
export function stripGradleComments(text: string): string {
  let result = "";
  let quote: string | null = null;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (quote !== null) {
      result += char;
      if (char === "\\" && i + 1 < text.length) {
        i += 1;
        result += text[i] as string;
      } else if (char === quote || char === "\n") {
        quote = null;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      result += char;
    } else if (char === "/" && text[i + 1] === "/") {
      const end = text.indexOf("\n", i);
      if (end === -1) break;
      i = end - 1;
    } else if (char === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end === -1) break;
      i = end + 1;
      result += " ";
    } else {
      result += char;
    }
  }
  return result;
}

const SPRING_PATTERN = /org\.springframework|spring-boot-starter/;

/** Gradle build scripts are only searched as text; they are never evaluated. */
export function detectGradleFrameworks(text: string): Framework[] {
  return SPRING_PATTERN.test(stripGradleComments(text)) ? ["Spring"] : [];
}

/** `gradle/libs.versions.toml` version catalogs: text search, `#` comments removed. */
export function detectGradleCatalogFrameworks(text: string): Framework[] {
  // Line by line: a `\s*` with the `m` flag would span newlines and go quadratic.
  const withoutComments = text
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
  return SPRING_PATTERN.test(withoutComments) ? ["Spring"] : [];
}

/** Lines of a requirements file: `name`, `name==1.0`, `name[extra]>=2`. Options (`-r`) are skipped. */
export function detectRequirementsFrameworks(text: string): {
  frameworks: Framework[];
  cut: boolean;
} {
  const frameworks = new Set<Framework>();
  const lines = text.split("\n");
  for (const line of lines.slice(0, MAX_REQUIREMENT_LINES)) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const name = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(trimmed)?.[1];
    const framework = name ? PYTHON_FRAMEWORKS[normalizePythonName(name)] : undefined;
    if (framework) frameworks.add(framework);
  }
  return { frameworks: [...frameworks], cut: lines.length > MAX_REQUIREMENT_LINES };
}

/**
 * `pyproject.toml` is not run through a TOML engine. A framework counts when its exact package
 * name appears as a whole token outside comments (`"flask>=3"`, `Django = "^4"`), so `flask-cors`
 * or `django-filter` do not match. A heuristic: it can over-report (a table named `flask`), which
 * only adds a note.
 */
export function detectPyprojectFrameworks(text: string): Framework[] {
  const frameworks = new Set<Framework>();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || /^name\s*=/.test(trimmed)) continue;
    for (const match of trimmed.matchAll(/(?<![\w.-])(django|flask|fastapi)(?![\w.-])/gi)) {
      const framework = PYTHON_FRAMEWORKS[(match[1] as string).toLowerCase()];
      if (framework) frameworks.add(framework);
    }
  }
  return [...frameworks];
}

/** `composer.json` is parsed as JSON; only the `require` tables are read. */
export function detectComposerFrameworks(text: string): Framework[] | "invalid_json" {
  let manifest: unknown;
  try {
    manifest = JSON.parse(text);
  } catch {
    return "invalid_json";
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) return [];
  const names = new Set<string>();
  for (const key of ["require", "require-dev"]) {
    const table = Object.hasOwn(manifest, key) ? (manifest as Record<string, unknown>)[key] : null;
    if (table && typeof table === "object" && !Array.isArray(table)) {
      for (const name of Object.keys(table)) names.add(name.toLowerCase());
    }
  }
  const frameworks: Framework[] = [];
  if (names.has("laravel/framework")) frameworks.push("Laravel");
  if (
    ["symfony/framework-bundle", "symfony/symfony", "symfony/http-kernel"].some((name) =>
      names.has(name),
    )
  ) {
    frameworks.push("Symfony");
  }
  return frameworks;
}

/**
 * Detects frameworks from dependency manifests, read-only. Nothing is installed, executed or
 * evaluated (no Maven/Gradle/pip/Composer). Each manifest is size-capped.
 */
export async function detectFrameworks(
  manifests: readonly ManifestFile[],
  maxBytes = MAX_MANIFEST_BYTES,
): Promise<FrameworkDetection> {
  const detection: FrameworkDetection = { frameworks: [], issues: [] };
  for (const manifest of manifests) {
    const text = await readTextFile(manifest.absolutePath, maxBytes);
    if (text === null) {
      detection.issues.push({ path: manifest.relativePath, reason: "unreadable_or_too_large" });
      continue;
    }
    const found = detectInManifest(manifest.kind, text);
    if (found.issue) detection.issues.push({ path: manifest.relativePath, reason: found.issue });
    for (const framework of found.frameworks) {
      detection.frameworks.push({ framework, manifestPath: manifest.relativePath });
    }
  }
  return detection;
}

function detectInManifest(
  kind: ManifestKind,
  text: string,
): { frameworks: Framework[]; issue?: ManifestIssueReason } {
  switch (kind) {
    case "maven": {
      const result = detectMavenFrameworks(text);
      return result === "unsafe_xml"
        ? { frameworks: [], issue: "unsafe_xml" }
        : { frameworks: result };
    }
    case "gradle":
      return { frameworks: detectGradleFrameworks(text) };
    case "python-requirements": {
      const result = detectRequirementsFrameworks(text);
      return result.cut
        ? { frameworks: result.frameworks, issue: "cut" }
        : { frameworks: result.frameworks };
    }
    case "gradle-catalog":
      return { frameworks: detectGradleCatalogFrameworks(text) };
    // Pipfile (TOML) and setup.py/setup.cfg are read as text and never executed: the token
    // heuristic of pyproject.toml applies (names in quotes or as keys, comments ignored).
    case "pyproject":
    case "pipfile":
    case "python-setup":
      return { frameworks: detectPyprojectFrameworks(text) };
    case "composer": {
      const result = detectComposerFrameworks(text);
      return result === "invalid_json"
        ? { frameworks: [], issue: "invalid_json" }
        : { frameworks: result };
    }
  }
}
