import { createHash } from "node:crypto";
import path from "node:path";
import type { AnalyzerOutput, Coverage, Finding } from "@pgard/findings";
import { createSourceFinding, type RawSourceFinding } from "./finding-factory.js";
import { analyzeGoSource } from "./go/analyze-go.js";
import { analyzeJsSource, type JsFileFacts } from "./js/analyze-js.js";
import { GO_RULE_IDS, JS_RULE_IDS, VUE_RULE_IDS } from "./rules.js";
import { detectLanguageTrack, languageTrackCoverage } from "./tree-sitter/language-track.js";
import { analyzeVueSource } from "./vue/analyze-vue.js";
import {
  readTextFile,
  walkSourceTree,
  type GeneratedDirectoryReason,
  type SkippedDependencyDirectory,
  type SourceLanguage,
} from "./walk.js";

export interface SourceScanOptions {
  signal?: AbortSignal;
  /** Wall-clock budget for the whole source scan; remaining files make coverage partial. */
  timeBudgetMs?: number;
  /** Injectable clock (ms) for tests. */
  now?: () => number;
}

const CSRF_MODULES = [
  "csurf",
  "csrf-csrf",
  "csrf-sync",
  "lusca",
  "tiny-csrf",
  "@fastify/csrf-protection",
  "@nestjs/csrf",
  "csrf",
];
const RATE_LIMIT_MODULES = [
  "express-rate-limit",
  "rate-limiter-flexible",
  "express-brute",
  "express-slow-down",
  "@nestjs/throttler",
  "@fastify/rate-limit",
  "limiter",
  "bottleneck",
  "hono-rate-limiter",
];
const JS_UNSUPPORTED_ORMS: Record<string, string> = {
  typeorm: "TypeORM",
  sequelize: "Sequelize",
  "drizzle-orm": "Drizzle",
  knex: "Knex",
  "@mikro-orm/core": "MikroORM",
  objection: "Objection.js",
  kysely: "Kysely",
};
const GO_UNSUPPORTED_ORMS: Record<string, string> = {
  "entgo.io/ent": "ent",
  "github.com/uptrace/bun": "Bun",
  "xorm.io/xorm": "XORM",
  "github.com/volatiletech/sqlboiler": "SQLBoiler",
  "github.com/go-pg/pg": "go-pg",
};
const LANGUAGE_LABEL: Record<SourceLanguage, string> = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  vue: "Vue",
  go: "Go",
};

interface LanguageStats {
  files: number;
  unparsable: number;
  unreadable: number;
  overran: number;
  /** Files that hit the per-file finding cap (relative paths). */
  cappedFiles: string[];
  skippedForTime: number;
}

const GENERATED_REASONS: ReadonlySet<string> = new Set<GeneratedDirectoryReason>([
  "Python virtual environment",
  "Python site-packages",
  "Maven build output",
  "Gradle cache",
]);
const MAX_LISTED_PATHS = 5;
/** The CLI shows at most 300 characters of a coverage note; the dependency note stays within. */
export const MAX_DEPENDENCY_NOTE_LENGTH = 300;
/** Longer directory paths in the dependency note keep their last characters. */
const MAX_LABEL_PATH_LENGTH = 60;

/**
 * Joins paths for a coverage note, listing at most MAX_LISTED_PATHS of them. Each path is quoted
 * (JSON string syntax) so names containing ", ", quotes or newlines stay unambiguous.
 */
function listPaths(paths: string[]): string {
  const listed = paths
    .slice(0, MAX_LISTED_PATHS)
    .map((item) => JSON.stringify(item))
    .join(", ");
  const rest = paths.length - MAX_LISTED_PATHS;
  return rest > 0 ? `${listed} and ${rest} more` : listed;
}

/**
 * Coverage note for the dependency directories the walk did not enter, listing at most
 * MAX_LISTED_PATHS of them: `vendor/ (composer.json), node_modules/`. Unusual names are quoted.
 */
export function describeSkippedDependencyDirectories(
  directories: readonly SkippedDependencyDirectory[],
): string {
  const label = (entry: SkippedDependencyDirectory) => {
    const directory =
      entry.path.length > MAX_LABEL_PATH_LENGTH
        ? `…${entry.path.slice(-(MAX_LABEL_PATH_LENGTH - 1))}`
        : entry.path;
    const name = /^[\w./@+-]+$/.test(directory) ? `${directory}/` : JSON.stringify(`${directory}/`);
    if (entry.reason === null) return name;
    if (entry.reason === "repository root") {
      return `${name} (repository root, no manifest; assumed third-party)`;
    }
    return `${name} (${entry.reason})`;
  };
  const count = directories.length;
  const generated = directories.some(
    (entry) => entry.reason !== null && GENERATED_REASONS.has(entry.reason),
  );
  const heading = `Skipped ${count} dependency director${count === 1 ? "y" : "ies"} (${generated ? "third-party or generated code" : "third-party code"}, not analyzed): `;
  const compose = (labels: string[]) => {
    const rest = count - labels.length;
    if (labels.length === 0) return `${heading}${count} not listed.`;
    return `${heading}${labels.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}.`;
  };
  // List fewer names rather than let a display limit cut off the "and N more" count.
  const labels: string[] = [];
  for (const entry of [...directories].sort((a, b) => a.path.localeCompare(b.path, "en"))) {
    if (labels.length === MAX_LISTED_PATHS) break;
    const next = [...labels, label(entry)];
    if (compose(next).length > MAX_DEPENDENCY_NOTE_LENGTH) break;
    labels.push(next[next.length - 1] as string);
  }
  return compose(labels);
}

/** Capitalizes the first letter so a clause can start a sentence in a note. */
function sentence(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
  }
}

function matchesModule(imports: Set<string>, candidates: string[]): boolean {
  return [...imports].some((name) =>
    candidates.some((candidate) => name === candidate || name.startsWith(`${candidate}/`)),
  );
}

/**
 * Scans the project's JavaScript/TypeScript/React, Vue and Go sources read-only and returns
 * findings plus per-language coverage. Project code is parsed, never executed or installed.
 */
export async function scanSourceCode(
  projectRoot: string,
  options: SourceScanOptions = {},
): Promise<AnalyzerOutput> {
  const walk = await walkSourceTree(projectRoot);
  const raw: RawSourceFinding[] = [];
  const stats: Record<SourceLanguage, LanguageStats> = {
    javascript: {
      files: 0,
      unparsable: 0,
      unreadable: 0,
      overran: 0,
      cappedFiles: [],
      skippedForTime: 0,
    },
    typescript: {
      files: 0,
      unparsable: 0,
      unreadable: 0,
      overran: 0,
      cappedFiles: [],
      skippedForTime: 0,
    },
    vue: { files: 0, unparsable: 0, unreadable: 0, overran: 0, cappedFiles: [], skippedForTime: 0 },
    go: { files: 0, unparsable: 0, unreadable: 0, overran: 0, cappedFiles: [], skippedForTime: 0 },
  };
  const jsFacts: { path: string; facts: JsFileFacts }[] = [];
  const goImports = new Set<string>();
  let jsxFiles = 0;

  const now = options.now ?? Date.now;
  const startedAt = now();
  const timeBudgetMs = options.timeBudgetMs ?? 120_000;
  for (const file of walk.files) {
    throwIfAborted(options.signal);
    const languageStats = stats[file.language];
    languageStats.files += 1;
    if (now() - startedAt > timeBudgetMs) {
      languageStats.skippedForTime += 1;
      continue;
    }
    const content = await readTextFile(file.absolutePath);
    if (content === null) {
      languageStats.unreadable += 1;
      continue;
    }
    try {
      let capped: string[] = [];
      if (file.language === "go") {
        const analysis = analyzeGoSource(content, file.relativePath);
        raw.push(...analysis.findings);
        for (const name of analysis.imports) goImports.add(name);
        if (analysis.hasParseErrors) languageStats.unparsable += 1;
        capped = analysis.cappedRules;
      } else if (file.language === "vue") {
        const analysis = analyzeVueSource(content, file.relativePath);
        raw.push(...analysis.findings);
        if (analysis.facts) jsFacts.push({ path: file.relativePath, facts: analysis.facts });
        if (analysis.hasParseErrors) languageStats.unparsable += 1;
        capped = analysis.cappedRules;
      } else {
        const analysis = analyzeJsSource(content, file.relativePath);
        raw.push(...analysis.findings);
        jsFacts.push({ path: file.relativePath, facts: analysis.facts });
        if (analysis.facts.hasJsx) jsxFiles += 1;
        if (analysis.hasParseErrors) languageStats.unparsable += 1;
        capped = analysis.cappedRules;
      }
      if (capped.length > 0) languageStats.cappedFiles.push(file.relativePath);
    } catch {
      languageStats.unparsable += 1;
    }
    // Checked after every file (including the last), so a slow file is always visible.
    throwIfAborted(options.signal);
    if (now() - startedAt > timeBudgetMs) languageStats.overran += 1;
  }

  // Dependency manifests for ORM detection (read-only, never executed).
  const declaredJsModules = new Set<string>();
  for (const relative of walk.packageJsonPaths) {
    const content = await readTextFile(path.join(projectRoot, relative), 2 * 1024 * 1024);
    try {
      const manifest = JSON.parse(content ?? "{}") as Record<string, unknown>;
      for (const key of [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
      ]) {
        const deps = manifest[key];
        if (deps && typeof deps === "object")
          for (const name of Object.keys(deps)) declaredJsModules.add(name);
      }
    } catch {
      // A malformed manifest only weakens ORM detection.
    }
  }
  const goModText = (
    await Promise.all(
      walk.goModPaths.map((relative) => readTextFile(path.join(projectRoot, relative))),
    )
  ).join("\n");

  // Cross-file heuristics (CSRF / brute force) — always suspected with low confidence.
  const allImports = new Set([
    ...declaredJsModules,
    ...jsFacts.flatMap((entry) => entry.facts.imports),
  ]);
  const hasCsrfProtection = matchesModule(allImports, CSRF_MODULES);
  const hasRateLimiter = matchesModule(allImports, RATE_LIMIT_MODULES);
  const usesCookieSession =
    jsFacts.some((entry) => entry.facts.usesCookieSession) ||
    matchesModule(allImports, ["express-session", "cookie-session", "cookie-parser"]);
  const firstRoute = jsFacts.find((entry) => entry.facts.stateChangingRoutes.length > 0);
  if (usesCookieSession && !hasCsrfProtection && firstRoute) {
    raw.push({
      ruleId: "PG-CSRF-001",
      path: firstRoute.path,
      line: firstRoute.facts.stateChangingRoutes[0] ?? 1,
      severity: "medium",
      status: "suspected",
      confidence: "low",
      evidence:
        "cookie-based session + state-changing route; no CSRF middleware import found in the project (a proxy or framework default may still protect it)",
      cause: "csrf-project",
    });
  }
  if (!hasRateLimiter) {
    for (const entry of jsFacts) {
      for (const route of entry.facts.authRoutes.slice(0, 5)) {
        raw.push({
          ruleId: "PG-BRUTE-001",
          path: entry.path,
          line: route.line,
          severity: "medium",
          status: "suspected",
          confidence: "low",
          evidence: `POST ${route.routePath.slice(0, 80)} with no rate-limiting library found in the project (a proxy or gateway may still limit it)`,
          cause: `brute:${route.routePath}`,
        });
      }
    }
  }

  const findings: Finding[] = raw.map(createSourceFinding);

  // Coverage.
  const coverage: Coverage[] = [];
  const languageCoverage = (language: SourceLanguage, ruleIds: string[], method: string) => {
    const languageStats = stats[language];
    const label = LANGUAGE_LABEL[language];
    const problems: string[] = [];
    if (languageStats.unparsable > 0)
      problems.push(
        `${languageStats.unparsable} file(s) had syntax errors and may be partially analyzed`,
      );
    if (languageStats.unreadable > 0)
      problems.push(`${languageStats.unreadable} file(s) were binary or unreadable`);
    if (languageStats.overran > 0)
      problems.push(`the time budget was exceeded while analyzing; results may be incomplete`);
    if (languageStats.cappedFiles.length > 0)
      problems.push(
        `${languageStats.cappedFiles.length} file(s) hit the per-file finding cap (${listPaths(languageStats.cappedFiles)}); further findings there are not listed`,
      );
    if (languageStats.skippedForTime > 0)
      problems.push(
        `${languageStats.skippedForTime} file(s) not analyzed because the time budget was used`,
      );
    if (walk.isTruncated) problems.push(`file limit reached; remaining files were not analyzed`);
    const isPartial = problems.length > 0;
    coverage.push({
      area: `source:${language}`,
      scope: "code",
      status: isPartial ? "partial" : "completed",
      ruleIds: languageStats.files > 0 ? ruleIds : [],
      note:
        languageStats.files === 0
          ? `No ${label} files found.`
          : `${languageStats.files} ${label} file(s); ${method}.${isPartial ? ` ${sentence(problems.join("; "))}.` : ""}`,
    });
  };
  const jsMethod = "TypeScript compiler AST with intra-file, flow-insensitive taint tracking";
  languageCoverage("javascript", JS_RULE_IDS, jsMethod);
  languageCoverage("typescript", JS_RULE_IDS, jsMethod);
  coverage.push({
    area: "source:react",
    scope: "code",
    status: "completed",
    ruleIds: jsxFiles > 0 ? ["PG-XSS-002"] : [],
    note:
      jsxFiles > 0
        ? `${jsxFiles} file(s) with JSX; analyzed with the JavaScript/TypeScript rules.`
        : "No JSX found.",
  });
  languageCoverage(
    "vue",
    [...VUE_RULE_IDS, ...JS_RULE_IDS],
    "script blocks via TypeScript AST, template v-html via @vue/compiler-sfc",
  );
  languageCoverage(
    "go",
    GO_RULE_IDS,
    "syntax-level heuristics (lexer and patterns, no type information or cross-file data flow)",
  );
  // Java, Kotlin, Python and PHP: detected only; no grammar is loaded until rules exist.
  coverage.push(...languageTrackCoverage(await detectLanguageTrack(walk)));
  if (walk.skippedLarge > 0) {
    coverage.push({
      area: "source:large-files",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: `${walk.skippedLarge} source file(s) over 1 MiB were skipped.`,
    });
  }
  if (walk.skippedSymlinks.length > 0) {
    // Informational: a later scan compares this note, so a link that replaced a file or a
    // directory (even with the same count) is noticed. The paths are hashed, not listed.
    coverage.push({
      area: "source:symlinks",
      scope: "code",
      status: "completed",
      ruleIds: [],
      note: `${walk.skippedSymlinks.length} symbolic link(s) were not followed (set ${fingerprintPaths(walk.skippedSymlinks)}).`,
    });
  }
  if (walk.unreadableDirectories.length > 0) {
    coverage.push({
      area: "source:unreadable",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: `${walk.unreadableDirectories.length} director${walk.unreadableDirectories.length === 1 ? "y" : "ies"} could not be read, so files below ${walk.unreadableDirectories.length === 1 ? "it were" : "them were"} not analyzed (set ${fingerprintPaths(walk.unreadableDirectories)}).`,
    });
  }
  if (walk.skippedDependencyDirectories.length > 0) {
    coverage.push({
      area: "source:dependency-directories",
      scope: "code",
      status: "completed",
      ruleIds: [],
      note: describeSkippedDependencyDirectories(walk.skippedDependencyDirectories),
    });
  }
  for (const [module, label] of Object.entries(JS_UNSUPPORTED_ORMS)) {
    if (allImports.has(module) || [...allImports].some((name) => name.startsWith(`${module}/`))) {
      coverage.push({
        area: `source:orm:${module}`,
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: `${label} detected; raw query analysis for ${label} is not supported, so its queries were not evaluated (not a safe result).`,
      });
    }
  }
  for (const [module, label] of Object.entries(GO_UNSUPPORTED_ORMS)) {
    if (goModText.includes(module) || [...goImports].some((name) => name.startsWith(module))) {
      coverage.push({
        area: `source:orm:${label.toLowerCase()}`,
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: `${label} detected; raw query analysis for ${label} is not supported, so its queries were not evaluated (not a safe result).`,
      });
    }
  }
  coverage.push({
    area: "source:heuristics",
    scope: "code",
    status: "completed",
    ruleIds: ["PG-CSRF-001", "PG-BRUTE-001"],
    note: "CSRF and brute-force checks are project-level heuristics (library imports and route names) and report suspected findings with low confidence.",
  });

  return { findings, coverage };
}

/** Short hash of a path set, so a note changes when the set changes without listing the paths. */
function fingerprintPaths(paths: readonly string[]): string {
  return createHash("sha256")
    .update([...paths].sort().join("\n"))
    .digest("hex")
    .slice(0, 8);
}
