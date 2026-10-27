import { createHash } from "node:crypto";
import path from "node:path";
import {
  compileGlob,
  compilePathMatcher,
  isTestOrFixturePath,
  isVendoredPath,
  matchesEverything,
  redactEvidence,
  type AnalyzerOutput,
  type CachedSourceFile,
  type Coverage,
  type Finding,
  type ProjectConfig,
  type RuleStat,
} from "@pgard/findings";
import { createSourceFinding, type RawSourceFinding } from "./finding-factory.js";
import { analyzeGoSource } from "./go/analyze-go.js";
import { analyzeJsSource, type JsFileFacts } from "./js/analyze-js.js";
import { GO_RULE_IDS, JS_RULE_IDS, VUE_RULE_IDS } from "./rules.js";
import { scanJvm, JVM_LANGUAGES } from "./jvm/scan-jvm.js";
import { scanPhp } from "./php/scan-php.js";
import { scanPython } from "./python/scan-python.js";
import {
  createTrackDeadline,
  MAX_TRACK_PARSE_MS,
  detectLanguageTrack,
  languageTrackCoverage,
} from "./tree-sitter/language-track.js";
import { analyzeVueSource } from "./vue/analyze-vue.js";
import {
  readTextFile,
  walkSourceTree,
  type SourceFile,
  type GeneratedDirectoryReason,
  type SkippedDependencyDirectory,
  type SourceLanguage,
  type WalkResult,
} from "./walk.js";

export interface SourceScanOptions {
  signal?: AbortSignal;
  /** Wall-clock budget for the whole source scan; remaining files make coverage partial. */
  timeBudgetMs?: number;
  /** Injectable clock (ms) for tests. */
  now?: () => number;
  /** Validated project configuration; its `exclude` patterns leave source files out, visibly. */
  projectConfig?: ProjectConfig | null;
  /**
   * Results of an earlier scan, by repository-relative path. A file whose path, language and
   * SHA-256 match an entry keeps that entry's result instead of being analyzed again; the
   * project-wide checks and every coverage note are still computed from all files.
   */
  reuse?: { files: ReadonlyMap<string, CachedSourceFile>; label: string } | null;
}

/** What a source scan hands back besides its findings: the cache for the next scan. */
export interface SourceScanOutput extends AnalyzerOutput {
  /** One entry per analyzed file, for a later scan to reuse. */
  fileCache: CachedSourceFile[];
  /** Files analyzed in this scan and files whose earlier result was reused. */
  reuse: { rescanned: number; reused: number };
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
  /** Files the language analyzer actually ran on (not skipped, unreadable or crashed). */
  analyzed: number;
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
export const MAX_NOTE_LENGTH = 300;
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
 * Shared shape of the counted-skip notes: `<heading>: "a", "b" and N more.<tail>`. At most
 * MAX_LISTED_PATHS paths are listed, fewer when long, so the count and the set fingerprint in the
 * heading are never cut off by a display limit. Paths are redacted before they are measured, so
 * the label that is measured is the label that is shown.
 */
function describeCappedPaths(
  heading: string,
  paths: readonly string[],
  tail: string,
  suffix = "",
): string {
  const count = paths.length;
  const compose = (labels: string[]) => {
    const rest = count - labels.length;
    if (labels.length === 0) return `${heading}${count} not listed.${tail}`;
    return `${heading}${labels.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}.${tail}`;
  };
  const labels: string[] = [];
  for (const raw of [...paths].sort((a, b) => a.localeCompare(b, "en"))) {
    if (labels.length === MAX_LISTED_PATHS) break;
    const item = redactEvidence(raw, { maxLength: 500 });
    const shown =
      item.length > MAX_LABEL_PATH_LENGTH ? `…${item.slice(-(MAX_LABEL_PATH_LENGTH - 1))}` : item;
    const next = [...labels, JSON.stringify(`${shown}${suffix}`)];
    if (compose(next).length > MAX_NOTE_LENGTH) break;
    labels.push(next[next.length - 1] as string);
  }
  return compose(labels);
}

const LIMIT_TAIL = " (file limit reached; count may be incomplete)";

/**
 * Coverage note for minified bundles the walk skipped: the count, the reason and at most
 * MAX_LISTED_PATHS paths (fewer when long, so the count is never cut off by a display limit).
 */
export function describeSkippedMinified(paths: readonly string[], limitReached = false): string {
  const count = paths.length;
  return describeCappedPaths(
    `${count} minified bundle${count === 1 ? "" : "s"} skipped (minified bundle, not analyzed; set ${fingerprintPaths(paths)}): `,
    paths,
    limitReached ? LIMIT_TAIL : "",
  );
}

/**
 * Coverage note for build-output and cache directories the walk did not enter. `pgard.config.json`
 * has no "include" option, so the note says how to get such a directory analyzed.
 */
export function describeSkippedBuildDirectories(
  paths: readonly string[],
  limitReached = false,
): string {
  const count = paths.length;
  return describeCappedPaths(
    `${count} build output director${count === 1 ? "y" : "ies"} skipped (build output, not analyzed; set ${fingerprintPaths(paths)}): `,
    paths,
    `${limitReached ? LIMIT_TAIL : ""} Not configurable; move first-party code out to analyze it.`,
    "/",
  );
}

/** Coverage note for `.xml` files under `res/` or `target/` that were not checked for mappers. */
export function describeSkippedResourceXml(paths: readonly string[], limitReached = false): string {
  const count = paths.length;
  return describeCappedPaths(
    `${count} XML file${count === 1 ? "" : "s"} under res/ or target/ not checked for MyBatis mappers (Android resources or build output, not analyzed; set ${fingerprintPaths(paths)}): `,
    paths,
    limitReached ? LIMIT_TAIL : "",
  );
}

/** Coverage note for files the walk could not stat, so they were not analyzed. */
export function describeUnreadableEntries(paths: readonly string[]): string {
  const count = paths.length;
  return describeCappedPaths(
    `${count} file${count === 1 ? "" : "s"} could not be read (permission error or removed during the scan, not analyzed; set ${fingerprintPaths(paths)}): `,
    paths,
    "",
  );
}

/** Coverage note for FIFOs, sockets and devices, which are never opened. */
export function describeSpecialFiles(paths: readonly string[]): string {
  const count = paths.length;
  return describeCappedPaths(
    `${count} special file${count === 1 ? "" : "s"} skipped (FIFO, socket, device or not a regular file, never opened; set ${fingerprintPaths(paths)}): `,
    paths,
    "",
  );
}

/**
 * Coverage note for the dependency directories the walk did not enter, listing at most
 * MAX_LISTED_PATHS of them: `vendor/ (composer.json), node_modules/`. Unusual names are quoted.
 */
export function describeSkippedDependencyDirectories(
  directories: readonly SkippedDependencyDirectory[],
): string {
  const label = (entry: SkippedDependencyDirectory) => {
    const redacted = redactEvidence(entry.path, { maxLength: 500 });
    const directory =
      redacted.length > MAX_LABEL_PATH_LENGTH
        ? `…${redacted.slice(-(MAX_LABEL_PATH_LENGTH - 1))}`
        : redacted;
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
    if (compose(next).length > MAX_NOTE_LENGTH) break;
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
 * The facts as they are kept, in a scan and in the stored state alike: a route path is redacted
 * like evidence (it ends up in finding evidence and in a finding's identity), so what is stored
 * never holds more than the result does, and a stored fact gives the same finding as a fresh one.
 */
function storableFacts(facts: JsFileFacts): Record<string, unknown> {
  return {
    ...facts,
    authRoutes: facts.authRoutes.map((route) => ({
      ...route,
      routePath: redactEvidence(route.routePath, { maxLength: 200 }),
    })),
  } as unknown as Record<string, unknown>;
}

/** Analyzes one file's text. Everything a later scan needs to reuse the result is in the entry. */
function analyzeFile(file: SourceFile, content: string, hash: string): CachedSourceFile {
  const base = { path: file.relativePath, language: file.language, hash };
  if (file.language === "go") {
    const analysis = analyzeGoSource(content, file.relativePath);
    return {
      ...base,
      findings: analysis.findings.map(createSourceFinding),
      facts: null,
      goImports: [...analysis.imports],
      hasJsx: false,
      hasParseErrors: analysis.hasParseErrors,
      capped: analysis.cappedRules.length > 0,
    };
  }
  if (file.language === "vue") {
    const analysis = analyzeVueSource(content, file.relativePath);
    return {
      ...base,
      findings: analysis.findings.map(createSourceFinding),
      facts: analysis.facts ? storableFacts(analysis.facts) : null,
      goImports: [],
      hasJsx: false,
      hasParseErrors: analysis.hasParseErrors,
      capped: analysis.cappedRules.length > 0,
    };
  }
  const analysis = analyzeJsSource(content, file.relativePath);
  return {
    ...base,
    findings: analysis.findings.map(createSourceFinding),
    facts: storableFacts(analysis.facts),
    goImports: [],
    hasJsx: analysis.facts.hasJsx,
    hasParseErrors: analysis.hasParseErrors,
    capped: analysis.cappedRules.length > 0,
  };
}

const isNumberList = (value: unknown): boolean =>
  Array.isArray(value) && value.every((item) => typeof item === "number");

/**
 * True when stored facts have the shape the project-wide checks read. A stored entry that fails
 * this is analyzed again instead of being trusted.
 */
function hasUsableFacts(entry: CachedSourceFile): boolean {
  if (entry.language === "go") return entry.facts === null;
  const facts = entry.facts;
  if (facts === null) return entry.language === "vue";
  return (
    Array.isArray(facts.imports) &&
    facts.imports.every((item: unknown) => typeof item === "string") &&
    isNumberList(facts.stateChangingRoutes) &&
    isNumberList(facts.preflightRoutes) &&
    (facts.preflightExposure === null ||
      facts.preflightExposure === "permissive" ||
      facts.preflightExposure === "unknown") &&
    typeof facts.strictSession === "boolean" &&
    typeof facts.usesCookieSession === "boolean" &&
    typeof facts.hasJsx === "boolean" &&
    Array.isArray(facts.authRoutes) &&
    facts.authRoutes.every(
      (route: unknown) =>
        typeof route === "object" &&
        route !== null &&
        typeof (route as { line?: unknown }).line === "number" &&
        typeof (route as { routePath?: unknown }).routePath === "string",
    )
  );
}

/**
 * Scans the project's JavaScript/TypeScript/React, Vue and Go sources read-only and returns
 * findings plus per-language coverage. Project code is parsed, never executed or installed.
 */
export async function scanSourceCode(
  projectRoot: string,
  options: SourceScanOptions = {},
): Promise<SourceScanOutput> {
  const excludePatterns = options.projectConfig?.exclude ?? [];
  const excludeMatcher = excludePatterns.length > 0 ? compilePathMatcher(excludePatterns) : null;
  const testPatterns = options.projectConfig?.testDirectories ?? [];
  const testMatcher = testPatterns.length > 0 ? compilePathMatcher(testPatterns) : null;
  const walk = await walkSourceTree(
    projectRoot,
    excludeMatcher ? { isExcluded: (relativePath) => excludeMatcher.matches(relativePath) } : {},
  );
  const findings: Finding[] = [];
  const fileCache: CachedSourceFile[] = [];
  let reusedFiles = 0;
  let rescannedFiles = 0;
  const reusedByLanguage: Record<SourceLanguage, number> = {
    javascript: 0,
    typescript: 0,
    vue: 0,
    go: 0,
  };
  const stats: Record<SourceLanguage, LanguageStats> = {
    javascript: {
      files: 0,
      analyzed: 0,
      unparsable: 0,
      unreadable: 0,
      overran: 0,
      cappedFiles: [],
      skippedForTime: 0,
    },
    typescript: {
      files: 0,
      analyzed: 0,
      unparsable: 0,
      unreadable: 0,
      overran: 0,
      cappedFiles: [],
      skippedForTime: 0,
    },
    vue: {
      files: 0,
      analyzed: 0,
      unparsable: 0,
      unreadable: 0,
      overran: 0,
      cappedFiles: [],
      skippedForTime: 0,
    },
    go: {
      files: 0,
      analyzed: 0,
      unparsable: 0,
      unreadable: 0,
      overran: 0,
      cappedFiles: [],
      skippedForTime: 0,
    },
  };
  const jsFacts: { path: string; facts: JsFileFacts }[] = [];
  const goImports = new Set<string>();
  let jsxFiles = 0;
  const jsxPaths = new Set<string>();
  const languageOfPath = new Map<string, SourceLanguage>();

  const now = options.now ?? Date.now;
  const startedAt = now();
  const timeBudgetMs = options.timeBudgetMs ?? 120_000;
  for (const file of walk.files) {
    throwIfAborted(options.signal);
    const languageStats = stats[file.language];
    languageStats.files += 1;
    languageOfPath.set(file.relativePath, file.language);
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
      // A file whose text is the one a stored scan analyzed (same path, language and SHA-256)
      // keeps that scan's result; anything else, or no stored scan, is analyzed now.
      const hash = createHash("sha256").update(content).digest("hex");
      const stored = options.reuse?.files.get(file.relativePath);
      let entry: CachedSourceFile;
      if (
        stored !== undefined &&
        stored.hash === hash &&
        stored.language === file.language &&
        hasUsableFacts(stored)
      ) {
        entry = stored;
        reusedFiles += 1;
        reusedByLanguage[file.language] += 1;
      } else {
        entry = analyzeFile(file, content, hash);
        rescannedFiles += 1;
      }
      fileCache.push(entry);
      findings.push(...entry.findings);
      if (entry.language === "go") {
        for (const name of entry.goImports) goImports.add(name);
      } else if (entry.facts !== null) {
        jsFacts.push({ path: file.relativePath, facts: entry.facts as unknown as JsFileFacts });
      }
      if (entry.hasJsx) {
        jsxFiles += 1;
        jsxPaths.add(file.relativePath);
      }
      if (entry.hasParseErrors) languageStats.unparsable += 1;
      languageStats.analyzed += 1;
      if (entry.capped) languageStats.cappedFiles.push(file.relativePath);
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

  // Project-wide heuristics (CSRF / brute force), always suspected with low confidence. They read
  // the facts of every file (reused ones included) and the manifests, so they run on every scan.
  const projectFindings: RawSourceFinding[] = [];
  const allImports = new Set([
    ...declaredJsModules,
    ...jsFacts.flatMap((entry) => entry.facts.imports),
  ]);
  const hasCsrfProtection = matchesModule(allImports, CSRF_MODULES);
  const hasRateLimiter = matchesModule(allImports, RATE_LIMIT_MODULES);
  // SameSite=Strict sessions keep the cookie off cross-site requests, so their mere import is not
  // enough; any other cookie-session library or configuration still counts.
  const strictSession = jsFacts.some((entry) => entry.facts.strictSession);
  const usesCookieSession =
    jsFacts.some((entry) => entry.facts.usesCookieSession) ||
    matchesModule(allImports, ["cookie-parser", "@fastify/session", "@fastify/secure-session"]) ||
    (!strictSession && matchesModule(allImports, ["express-session", "cookie-session"]));
  // PUT/PATCH/DELETE need a CORS preflight: they count unless CORS is provably restrictive (no
  // CORS, a fixed origin list, no credentials). Unresolvable CORS, hand-set credential headers and
  // method-override (a form POST reaches DELETE) keep them in, as the preflight cannot be assumed.
  const preflightExposure = jsFacts.some((entry) => entry.facts.preflightExposure === "permissive")
    ? "permissive"
    : jsFacts.some((entry) => entry.facts.preflightExposure === "unknown") ||
        matchesModule(allImports, ["method-override"])
      ? "unknown"
      : null;
  const csrfRoutesOf = (facts: (typeof jsFacts)[number]["facts"]) => [
    ...facts.stateChangingRoutes,
    ...(preflightExposure ? facts.preflightRoutes : []),
  ];
  const firstRoute = jsFacts.find((entry) => csrfRoutesOf(entry.facts).length > 0);
  if (usesCookieSession && !hasCsrfProtection && firstRoute) {
    projectFindings.push({
      ruleId: "PG-CSRF-001",
      path: firstRoute.path,
      line: Math.min(...csrfRoutesOf(firstRoute.facts)),
      severity: "medium",
      status: "suspected",
      confidence: "low",
      evidence: `cookie-based session + state-changing route${
        firstRoute.facts.stateChangingRoutes.length === 0
          ? ` (PUT/PATCH/DELETE counted: CORS ${preflightExposure === "permissive" ? "allows any origin with credentials" : "or method-override cannot be shown to block cross-site requests"})`
          : ""
      }; no CSRF middleware import found in the project (a proxy or framework default may still protect it)`,
      cause: "csrf-project",
    });
  }
  if (!hasRateLimiter) {
    for (const entry of jsFacts) {
      for (const route of entry.facts.authRoutes.slice(0, 5)) {
        projectFindings.push({
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

  findings.push(...projectFindings.map(createSourceFinding));

  // Coverage.
  const coverage: Coverage[] = [];
  // Rule stats: one row per rule and area that ran. Targets are the files the analyzers really
  // ran on, counted in the walk above; findings are the rule's own raw findings in those files.
  const ruleStats: RuleStat[] = [];
  const addRuleStats = (
    entry: Coverage,
    examined: number,
    isInArea: (finding: Finding) => boolean,
  ) => {
    if (entry.status !== "completed" && entry.status !== "partial") return;
    for (const ruleId of entry.ruleIds) {
      ruleStats.push({
        ruleId,
        area: entry.area,
        scope: "code",
        status: entry.status,
        targets: [{ unit: "files", examined, reason: null }],
        findings: findings.filter((finding) => finding.ruleId === ruleId && isInArea(finding))
          .length,
      });
    }
  };
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
    const entry: Coverage = {
      area: `source:${language}`,
      scope: "code",
      status: isPartial ? "partial" : "completed",
      ruleIds: languageStats.files > 0 ? ruleIds : [],
      note:
        languageStats.files === 0
          ? `No ${label} files found.`
          : `${languageStats.files} ${label} file(s); ${method}.${isPartial ? ` ${sentence(problems.join("; "))}.` : ""}${reusedByLanguage[language] > 0 && options.reuse ? ` ${reusedByLanguage[language]} file(s) reused from scan ${options.reuse.label} (content unchanged).` : ""}`,
    };
    coverage.push(entry);
    addRuleStats(
      entry,
      languageStats.analyzed,
      (finding) => languageOfPath.get(finding.location.path ?? "") === language,
    );
  };
  const jsMethod = "TypeScript compiler AST with intra-file, flow-insensitive taint tracking";
  languageCoverage("javascript", JS_RULE_IDS, jsMethod);
  languageCoverage("typescript", JS_RULE_IDS, jsMethod);
  const reactEntry: Coverage = {
    area: "source:react",
    scope: "code",
    status: "completed",
    ruleIds: jsxFiles > 0 ? ["PG-XSS-002"] : [],
    note:
      jsxFiles > 0
        ? `${jsxFiles} file(s) with JSX; analyzed with the JavaScript/TypeScript rules.`
        : "No JSX found.",
  };
  coverage.push(reactEntry);
  addRuleStats(reactEntry, jsxFiles, (finding) => jsxPaths.has(finding.location.path ?? ""));
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
  // Java, Kotlin (and MyBatis mapper XML), Python and PHP have rules; any other language is only
  // detected, and no grammar is loaded for a language without rules. Java and Kotlin go through
  // `parseTrackFiles` inside `scanJvm`, so a grammar that fails its checksum, an oversized file or
  // a timeout shows up as a partial or not_tested area, never as a safe result.
  const detection = await detectLanguageTrack(walk);
  const jvm = await scanJvm(walk, detection, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    deadline: createTrackDeadline(Math.min(MAX_TRACK_PARSE_MS, timeBudgetMs)),
    ...(excludeMatcher === null
      ? {}
      : { isExcluded: (relativePath: string) => excludeMatcher.matches(relativePath) }),
  });
  findings.push(...jvm.findings);
  coverage.push(...jvm.coverage);
  ruleStats.push(...jvm.ruleStats);
  const php = await scanPhp(walk, detection, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    deadline: createTrackDeadline(Math.min(MAX_TRACK_PARSE_MS, timeBudgetMs)),
  });
  findings.push(...php.findings);
  coverage.push(...php.coverage);
  ruleStats.push(...php.ruleStats);
  const python = await scanPython(walk, detection, {
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    deadline: createTrackDeadline(Math.min(MAX_TRACK_PARSE_MS, timeBudgetMs)),
  });
  findings.push(...python.findings);
  coverage.push(...python.coverage);
  ruleStats.push(...python.ruleStats);
  coverage.push(...languageTrackCoverage(detection, new Set([...JVM_LANGUAGES, "python", "php"])));
  const excludedTotal = {
    count: walk.excluded.count + jvm.excludedMapperPaths.length,
    digest:
      jvm.excludedMapperPaths.length === 0
        ? walk.excluded.digest
        : fingerprintPaths([walk.excluded.digest, ...jvm.excludedMapperPaths]),
  };
  if (excludeMatcher !== null) {
    coverage.push(
      describeConfigExcluded(
        excludePatterns,
        excludedTotal,
        walk.files.length +
          walkTrackedCount(walk) +
          jvm.mapperFiles +
          jvm.templateFiles +
          excludedTotal.count,
        excludeMatcher.exhausted,
      ),
    );
  }
  if (testMatcher !== null) {
    const analyzed = [
      ...walk.files.map((file) => file.relativePath),
      ...Object.values(walk.trackFiles).flatMap((list) => list.map((file) => file.relativePath)),
      ...jvm.analyzedPaths.filter((analyzed) => analyzed.endsWith(".xml")),
    ];
    coverage.push(
      describeConfigTestDirectories(
        testPatterns,
        analyzed,
        testMatcher.matches,
        () => testMatcher.exhausted,
      ),
    );
  }
  if (excludeMatcher?.exhausted === true || testMatcher?.exhausted === true) {
    coverage.push({
      area: "source:config",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: CONFIG_BUDGET_NOTE,
    });
  }
  if (walk.skippedLarge > 0) {
    coverage.push({
      area: "source:large-files",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: `${walk.skippedLarge} source file(s) over 1 MiB were skipped.`,
    });
  }
  if (walk.skippedMinified.length > 0) {
    coverage.push({
      area: "source:minified",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: describeSkippedMinified(walk.skippedMinified, walk.isTruncated),
    });
  }
  const limitReached = walk.isTruncated;
  const unanalyzed = walk.files.length + walkTrackedCount(walk) === 0;
  if (walk.skippedBuildDirectories.length > 0) {
    // Informational like the dependency directories: build output is generated, so skipping it
    // does not make a scan partial. Exception: when no source file was found anywhere, the only
    // source may live in such a directory (a first-party `build/` or `out/` package), and
    // then the scan says so by being partial.
    coverage.push({
      area: "source:build-output",
      scope: "code",
      status: unanalyzed ? "partial" : "completed",
      ruleIds: [],
      note: describeSkippedBuildDirectories(walk.skippedBuildDirectories, limitReached),
    });
  }
  if (walk.skippedResourceXml.length > 0) {
    coverage.push({
      area: "source:xml-skipped",
      scope: "code",
      status: "completed",
      ruleIds: [],
      note: describeSkippedResourceXml(walk.skippedResourceXml, limitReached),
    });
  }
  if (walk.unreadableEntries.length > 0) {
    coverage.push({
      area: "source:unreadable-files",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: describeUnreadableEntries(walk.unreadableEntries),
    });
  }
  if (walk.skippedSpecialFiles.length > 0) {
    coverage.push({
      area: "source:special-files",
      scope: "code",
      status: "completed",
      ruleIds: [],
      note: describeSpecialFiles(walk.skippedSpecialFiles),
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
  // The heuristics read the facts of every analyzed JavaScript, TypeScript and Vue file, so they
  // are only as complete as those areas: partial when one of them was, and not run (no rules
  // listed, like a language with no files) when there was nothing to read.
  const jsFamilyAreas = ["source:javascript", "source:typescript", "source:vue"];
  const isJsFamilyPartial = coverage.some(
    (entry) => jsFamilyAreas.includes(entry.area) && entry.status === "partial",
  );
  const hasHeuristicsInput = jsFacts.length > 0;
  const heuristicsEntry: Coverage = {
    area: "source:heuristics",
    scope: "code",
    status: isJsFamilyPartial ? "partial" : "completed",
    ruleIds: hasHeuristicsInput ? ["PG-CSRF-001", "PG-BRUTE-001"] : [],
    note: hasHeuristicsInput
      ? `CSRF and brute-force checks are project-level heuristics (library imports and route names) and report suspected findings with low confidence.${isJsFamilyPartial ? " Partial because a JavaScript, TypeScript or Vue area was partial." : ""}`
      : "No JavaScript, TypeScript or Vue files were analyzed, so the CSRF and brute-force heuristics did not run.",
  };
  coverage.push(heuristicsEntry);
  // The heuristics read the facts of every analyzed JavaScript, TypeScript and Vue file.
  addRuleStats(heuristicsEntry, jsFacts.length, () => true);

  return {
    findings,
    coverage,
    ruleStats,
    fileCache,
    reuse: { rescanned: rescannedFiles, reused: reusedFiles },
  };
}

function walkTrackedCount(walk: WalkResult): number {
  return Object.values(walk.trackFiles).reduce((sum, list) => sum + list.length, 0);
}

/** The CLI shows at most 300 characters of a coverage note; the count comes first. */
export const MAX_CONFIG_NOTE_LENGTH = 300;

/**
 * Coverage entry for files left out by `pgard.config.json`: the count, the share of all source
 * files found, a hash of the patterns and of the excluded file set (so a later scan notices a
 * different set even when the count is the same) and the patterns themselves, JSON-quoted. A
 * pattern that matches every file, or exclusions that leave nothing analyzed, make the area
 * `partial` with a WARNING: the scan then says little about the project.
 */
export function describeConfigExcluded(
  patterns: readonly string[],
  excluded: { count: number; digest: string },
  totalFound: number,
  budgetExhausted = false,
): Coverage {
  const catchAll = patterns.filter((pattern) => matchesEverything(compileGlob(pattern)));
  const everythingExcluded = totalFound > 0 && excluded.count === totalFound;
  const setHash = createHash("sha256")
    .update(`${[...patterns].sort().join("\n")}\n--\n${excluded.digest}`)
    .digest("hex")
    .slice(0, 16);
  const count = excluded.count;
  const warning =
    (catchAll.length > 0
      ? ` WARNING: ${JSON.stringify(catchAll[0])} matches every file.`
      : everythingExcluded
        ? " WARNING: every source file is excluded."
        : "") + (budgetExhausted ? ` WARNING: ${BUDGET_WARNING}` : "");
  const heading = `${count} file${count === 1 ? "" : "s"} excluded by pgard.config.json (of ${totalFound} source files; ${patterns.length} pattern${patterns.length === 1 ? "" : "s"}, set ${setHash}).${warning}`;
  const compose = (shown: string[]) => {
    const rest = patterns.length - shown.length;
    return `${heading} Patterns: ${shown.map((pattern) => JSON.stringify(pattern)).join(", ")}${rest > 0 ? ` and ${rest} more` : ""}.`;
  };
  const shown: string[] = [];
  for (const pattern of patterns) {
    if (shown.length === MAX_LISTED_PATHS) break;
    if (compose([...shown, pattern]).length > MAX_CONFIG_NOTE_LENGTH) break;
    shown.push(pattern);
  }
  return {
    area: "source:config-excluded",
    scope: "code",
    status: warning === "" ? "completed" : "partial",
    ruleIds: [],
    note: shown.length === 0 ? heading : compose(shown),
  };
}

const BUDGET_WARNING =
  "pattern matching hit its work limit; later files were NOT excluded or reclassified.";
/** Merged into the `source:config` note by the scan (one entry per area). */
export const CONFIG_BUDGET_NOTE =
  "WARNING: the patterns in pgard.config.json exceeded the matching work limit (too many or too expensive patterns). Files after that point were scanned as if no pattern applied to them; simplify the patterns.";

/** At or above this share of production files (and more than MIN files) the config is suspect. */
export const CONFIG_TEST_SHARE_WARNING = 0.5;
export const CONFIG_TEST_MIN_FILES = 20;

/**
 * Coverage entry `source:config-test` for `testDirectories`. It counts the files the patterns
 * demote from regular code to test code (files that the built-in rules do not already treat as
 * test or vendored). Test code is listed apart and its confidence is capped at low, so a config
 * that marks all or most production files as test code would make real findings look minor: when
 * the patterns match every such file, or at least half of them and more than 20, the area is
 * `partial` with a WARNING (a real project keeps most of its code outside test paths).
 */
export function describeConfigTestDirectories(
  patterns: readonly string[],
  analyzedPaths: readonly string[],
  matches: (filePath: string) => boolean,
  isExhausted: () => boolean = () => false,
): Coverage {
  const production = analyzedPaths.filter(
    (filePath) => !isTestOrFixturePath(filePath) && !isVendoredPath(filePath),
  );
  const demoted = production.filter(matches).length;
  const budgetExhausted = isExhausted();
  const isSuspect =
    production.length > 0 &&
    (demoted === production.length ||
      (demoted > CONFIG_TEST_MIN_FILES &&
        demoted / production.length >= CONFIG_TEST_SHARE_WARNING));
  const setHash = createHash("sha256")
    .update(`${[...patterns].sort().join("\n")}\n--\n${demoted}`)
    .digest("hex")
    .slice(0, 16);
  const listed = patterns.slice(0, MAX_LISTED_PATHS).map((pattern) => JSON.stringify(pattern));
  const rest = patterns.length - listed.length;
  const note =
    `${demoted} of ${production.length} source files are classified as test code by pgard.config.json testDirectories (set ${setHash}).` +
    (isSuspect ? " WARNING: most or all of your code is marked as test code." : "") +
    (budgetExhausted ? ` WARNING: ${BUDGET_WARNING}` : "") +
    ` Patterns: ${listed.join(", ")}${rest > 0 ? ` and ${rest} more` : ""}.`;
  return {
    area: "source:config-test",
    scope: "code",
    status: isSuspect || budgetExhausted ? "partial" : "completed",
    ruleIds: [],
    note:
      note.length > MAX_CONFIG_NOTE_LENGTH
        ? `${note.slice(0, MAX_CONFIG_NOTE_LENGTH - 3)}...`
        : note,
  };
}

/** Short hash of a path set, so a note changes when the set changes without listing the paths. */
function fingerprintPaths(paths: readonly string[]): string {
  return createHash("sha256")
    .update([...paths].sort().join("\n"))
    .digest("hex")
    .slice(0, 8);
}
