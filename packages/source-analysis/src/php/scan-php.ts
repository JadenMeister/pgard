import type { Coverage, Finding, RuleStat } from "@pgard/findings";
import { createSourceFinding } from "../finding-factory.js";
import { PHP_RULE_IDS } from "../rules.js";
import { detectPhpNamespaceFrameworks, type Framework } from "../tree-sitter/detect-frameworks.js";
import {
  parseCoverage,
  parseTrackFiles,
  type LanguageTrackDetection,
  type TrackDeadline,
} from "../tree-sitter/language-track.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import type { WalkResult } from "../walk.js";
import { analyzePhpTree } from "./analyze-php.js";

export interface PhpScanOptions {
  signal?: AbortSignal;
  deadline: TrackDeadline;
}

export interface PhpScanOutput {
  findings: Finding[];
  coverage: Coverage[];
  ruleStats: RuleStat[];
  /** PHP files that were parsed. */
  analyzedPaths: string[];
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
  }
}

const METHOD =
  "tree-sitter syntax trees, intra-procedural source-to-sink tracking for SQL injection (PG-SQL-007) and OS command execution (PG-CMD-005); no cross-file data flow";
/** Categories with PHP files present but no PHP rule yet. */
const NOT_CHECKED =
  "Not checked yet for PHP: XSS (echo of request data, Blade {!! !!}), file inclusion and path, SSRF, cryptography and settings.";

const isBlade = (relativePath: string): boolean => relativePath.endsWith(".blade.php");

/**
 * Parses and analyzes the PHP files of a walk with the SQL injection and command execution rules.
 * Files go through `parseTrackFiles`, so oversized, unreadable and timed-out files and a grammar
 * that fails its checksum make the area partial or not tested, never "safe". Files are analyzed
 * again on every scan (no result is cached).
 */
export async function scanPhp(
  walk: WalkResult,
  detection: LanguageTrackDetection,
  options: PhpScanOptions,
): Promise<PhpScanOutput> {
  const files = walk.trackFiles.php;
  const output: PhpScanOutput = { findings: [], coverage: [], ruleStats: [], analyzedPaths: [] };
  if (files.length === 0) return output;
  throwIfAborted(options.signal);
  const runtime = new TreeSitterRuntime();
  try {
    const own: Finding[] = [];
    const cappedFiles: string[] = [];
    const incompleteFiles: string[] = [];
    const errorFiles: string[] = [];
    const formFiles: string[] = [];
    const libraries = new Map<string, { kind: "sql" | "process"; count: number }>();
    const namespaceFrameworks = new Set<Framework>();
    let crashed = 0;
    const stats = await parseTrackFiles(
      runtime,
      "php",
      files,
      { deadline: options.deadline },
      (file, outcome, source) => {
        throwIfAborted(options.signal);
        try {
          const analysis = analyzePhpTree(outcome.tree.rootNode, source, file.relativePath);
          output.analyzedPaths.push(file.relativePath);
          if (outcome.errorCount > 0) errorFiles.push(file.relativePath);
          own.push(...analysis.findings.map(createSourceFinding));
          if (analysis.capped) cappedFiles.push(file.relativePath);
          if (analysis.incomplete) incompleteFiles.push(file.relativePath);
          if (analysis.unsupportedForms.length > 0) formFiles.push(file.relativePath);
          for (const library of analysis.unsupportedLibraries) {
            const known = libraries.get(library.label);
            libraries.set(library.label, {
              kind: library.kind,
              count: (known?.count ?? 0) + 1,
            });
          }
          for (const framework of detectPhpNamespaceFrameworks(source)) {
            namespaceFrameworks.add(framework);
          }
        } catch {
          crashed += 1;
        }
      },
    );
    output.findings.push(...own);
    const base = parseCoverage("php", PHP_RULE_IDS, stats);
    const problems: string[] = [];
    if (cappedFiles.length > 0) {
      problems.push(
        `${cappedFiles.length} file(s) hit the per-file finding cap (25 findings per rule per file); further findings there are not listed`,
      );
    }
    if (incompleteFiles.length > 0) {
      problems.push(
        `${incompleteFiles.length} file(s) were nested too deeply, or too large, to analyze in full`,
      );
    }
    if (formFiles.length > 0) {
      problems.push(
        `${formFiles.length} file(s) have SQL-looking calls through dynamic call forms ($fn(...), $object->$method(...), call_user_func) that are not followed (${formFiles.slice(0, 3).join(", ")})`,
      );
    }
    if (errorFiles.length > 0) {
      problems.push(
        `${errorFiles.length} file(s) have syntax errors that the parser could not recover from cleanly (${errorFiles.slice(0, 3).join(", ")})`,
      );
    }
    if (crashed > 0) problems.push(`${crashed} file(s) could not be analyzed`);
    if (base.status === "not_tested") {
      output.coverage.push(base);
      return output;
    }
    const frameworks = [
      ...new Set([
        ...(detection.languages.find((entry) => entry.language === "php")?.frameworks ?? []),
        ...namespaceFrameworks,
      ]),
    ];
    const lowerBound = detection.truncated ? "at least " : "";
    const note = [
      `${lowerBound}${files.length} PHP file(s)${frameworks.length > 0 ? `; frameworks: ${frameworks.join(", ")}` : ""}; ${METHOD}.`,
      NOT_CHECKED,
      base.note,
      problems.length > 0
        ? `${problems.join("; ")}. Those files were analyzed only in part and are not a safe result.`
        : null,
    ]
      .filter((part): part is string => part !== null)
      .join(" ");
    const entry: Coverage = {
      ...base,
      status: base.status === "partial" || problems.length > 0 ? "partial" : "completed",
      note,
    };
    output.coverage.push(entry);
    for (const ruleId of entry.ruleIds) {
      output.ruleStats.push({
        ruleId,
        area: entry.area,
        scope: "code",
        status: entry.status as "completed" | "partial",
        targets: [{ unit: "files", examined: stats.parsed, reason: null }],
        findings: own.filter((finding) => finding.ruleId === ruleId).length,
      });
    }
    const blade = files.filter((file) => isBlade(file.relativePath)).length;
    if (blade > 0) {
      output.coverage.push({
        area: "source:php:blade",
        scope: "code",
        status: "not_tested",
        ruleIds: [],
        note: `${blade} Blade template(s) detected. Only their <?php ?> blocks were parsed; Blade directives and output ({{ }}, {!! !!}, @php) are not analyzed, and the Blade XSS checks come later. This is not a safe result.`,
      });
    }
    for (const [library, { kind, count }] of libraries) {
      output.coverage.push({
        area: `source:${kind === "sql" ? "orm" : "process"}:${library.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        scope: "code",
        status: "partial",
        ruleIds: kind === "sql" ? ["PG-SQL-007"] : ["PG-CMD-005"],
        note: `${library} detected in ${count} file(s); its ${
          kind === "sql" ? "SQL" : "process-running"
        } APIs are not supported, so ${
          kind === "sql" ? "queries" : "commands run"
        } through it were not evaluated (not a safe result).`,
      });
    }
    return output;
  } finally {
    runtime.dispose();
  }
}
