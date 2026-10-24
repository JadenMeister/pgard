import path from "node:path";
import type { AnalyzerOutput, Coverage, Finding } from "@pgard/findings";
import { createSourceFinding, type RawSourceFinding } from "./finding-factory.js";
import { analyzeGoSource } from "./go/analyze-go.js";
import { analyzeJsSource, type JsFileFacts } from "./js/analyze-js.js";
import { GO_RULE_IDS, JS_RULE_IDS, VUE_RULE_IDS } from "./rules.js";
import { analyzeVueSource } from "./vue/analyze-vue.js";
import { readTextFile, walkSourceTree, type SourceLanguage } from "./walk.js";

export interface SourceScanOptions {
  signal?: AbortSignal;
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
    javascript: { files: 0, unparsable: 0, unreadable: 0 },
    typescript: { files: 0, unparsable: 0, unreadable: 0 },
    vue: { files: 0, unparsable: 0, unreadable: 0 },
    go: { files: 0, unparsable: 0, unreadable: 0 },
  };
  const jsFacts: { path: string; facts: JsFileFacts }[] = [];
  const goImports = new Set<string>();
  let jsxFiles = 0;

  for (const file of walk.files) {
    throwIfAborted(options.signal);
    const languageStats = stats[file.language];
    languageStats.files += 1;
    const content = await readTextFile(file.absolutePath);
    if (content === null) {
      languageStats.unreadable += 1;
      continue;
    }
    try {
      if (file.language === "go") {
        const analysis = analyzeGoSource(content, file.relativePath);
        raw.push(...analysis.findings);
        for (const name of analysis.imports) goImports.add(name);
      } else if (file.language === "vue") {
        const analysis = analyzeVueSource(content, file.relativePath);
        raw.push(...analysis.findings);
        if (analysis.facts) jsFacts.push({ path: file.relativePath, facts: analysis.facts });
        if (analysis.hasParseErrors) languageStats.unparsable += 1;
      } else {
        const analysis = analyzeJsSource(content, file.relativePath);
        raw.push(...analysis.findings);
        jsFacts.push({ path: file.relativePath, facts: analysis.facts });
        if (analysis.facts.hasJsx) jsxFiles += 1;
        if (analysis.hasParseErrors) languageStats.unparsable += 1;
      }
    } catch {
      languageStats.unparsable += 1;
    }
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
          : `${languageStats.files} ${label} file(s); ${method}.${isPartial ? ` ${problems.join("; ")}.` : ""}`,
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
  if (walk.skippedLarge > 0) {
    coverage.push({
      area: "source:large-files",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: `${walk.skippedLarge} source file(s) over 1 MiB were skipped.`,
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
