import { coverageNote, type Coverage, type Finding, type RuleStat } from "@pgard/findings";
import { createSourceFinding } from "../finding-factory.js";
import { PYTHON_RULE_IDS } from "../rules.js";
import {
  parseCoverage,
  parseTrackFiles,
  type LanguageTrackDetection,
  type TrackDeadline,
} from "../tree-sitter/language-track.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import type { TrackedFile, WalkResult } from "../walk.js";
import { analyzePythonTree } from "./analyze-python.js";

export interface PythonScanOptions {
  signal?: AbortSignal;
  deadline: TrackDeadline;
}

export interface PythonScanOutput {
  findings: Finding[];
  coverage: Coverage[];
  ruleStats: RuleStat[];
  /** Python files that were parsed and analyzed. */
  analyzedPaths: string[];
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
  }
}

const METHOD =
  "tree-sitter syntax trees, intra-procedural source-to-sink tracking for SQL injection (PG-SQL-006) and OS command execution (PG-CMD-004); no cross-file data flow";

export const PYTHON_OTHER_CATEGORIES_NOTE =
  "Python cross-site scripting (Jinja2 |safe, Markup, mark_safe), SSRF, path traversal, cryptography and settings checks (DEBUG, SECRET_KEY, ALLOWED_HOSTS) are not implemented yet, so a clean Python result says nothing about them.";

const label = (name: string): string => name.toLowerCase().replace(/[^a-z0-9]+/g, "-");

/**
 * Parses and analyzes the Python files of a walk with the SQL injection and command execution
 * rules. The files go through `parseTrackFiles`, so oversized, unreadable and timed-out files and
 * a grammar that fails its checksum make the area partial or not tested, never "safe". Files are
 * analyzed again on every scan (no result is cached).
 */
export async function scanPython(
  walk: WalkResult,
  detection: LanguageTrackDetection,
  options: PythonScanOptions,
): Promise<PythonScanOutput> {
  const files: readonly TrackedFile[] = walk.trackFiles.python;
  const out: PythonScanOutput = { findings: [], coverage: [], ruleStats: [], analyzedPaths: [] };
  if (files.length === 0) return out;
  const runtime = new TreeSitterRuntime();
  try {
    throwIfAborted(options.signal);
    const manifestFrameworks =
      detection.languages.find((entry) => entry.language === "python")?.frameworks ?? [];
    const cappedFiles: string[] = [];
    const incompleteFiles: string[] = [];
    const errorFiles: string[] = [];
    const formFiles = new Map<string, string[]>();
    const libraries = new Map<string, number>();
    const processLibraries = new Map<string, number>();
    const imported = new Set<string>();
    let crashed = 0;
    const stats = await parseTrackFiles(
      runtime,
      "python",
      files,
      { deadline: options.deadline },
      (file, outcome, source) => {
        throwIfAborted(options.signal);
        try {
          const analysis = analyzePythonTree(outcome.tree.rootNode, source, file.relativePath, {
            django: manifestFrameworks.includes("Django"),
          });
          out.analyzedPaths.push(file.relativePath);
          if (outcome.errorCount > 0 || outcome.missingCount > 0)
            errorFiles.push(file.relativePath);
          out.findings.push(...analysis.findings.map(createSourceFinding));
          if (analysis.capped) cappedFiles.push(file.relativePath);
          if (analysis.incomplete) incompleteFiles.push(file.relativePath);
          for (const form of analysis.unsupportedForms) {
            formFiles.set(form, [...(formFiles.get(form) ?? []), file.relativePath]);
          }
          for (const library of analysis.unsupportedLibraries) {
            libraries.set(library, (libraries.get(library) ?? 0) + 1);
          }
          for (const library of analysis.unsupportedProcessLibraries) {
            processLibraries.set(library, (processLibraries.get(library) ?? 0) + 1);
          }
          for (const framework of analysis.frameworks) imported.add(framework);
        } catch {
          crashed += 1;
        }
      },
    );
    const base = parseCoverage("python", PYTHON_RULE_IDS, stats);
    const problems: string[] = [];
    if (cappedFiles.length > 0) {
      problems.push(
        `${cappedFiles.length} file(s) hit the per-file finding cap (25 findings per rule per file); further findings there are not listed`,
      );
    }
    if (incompleteFiles.length > 0) {
      problems.push(
        `${incompleteFiles.length} file(s) were nested too deeply to analyze in full (${incompleteFiles.slice(0, 3).join(", ")})`,
      );
    }
    for (const [form, paths] of formFiles) {
      problems.push(
        `${paths.length} file(s) have ${form} whose target cannot be seen, so a SQL or command call through them is not followed (${[...new Set(paths)].slice(0, 3).join(", ")})`,
      );
    }
    if (errorFiles.length > 0) {
      problems.push(
        `${errorFiles.length} file(s) have syntax errors that the parser could not recover from cleanly (${errorFiles.slice(0, 3).join(", ")})`,
      );
    }
    if (crashed > 0) problems.push(`${crashed} file(s) could not be analyzed`);
    if (base.status === "not_tested") {
      out.coverage.push(base);
      return out;
    }
    const frameworks = [...new Set<string>([...manifestFrameworks, ...imported])];
    const detected = frameworks.length > 0 ? `; frameworks: ${frameworks.join(", ")}` : "";
    const lowerBound = detection.truncated ? "at least " : "";
    const note = [
      `${lowerBound}${files.length} Python file(s)${detected}; ${METHOD}.`,
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
    out.coverage.push(entry);
    for (const ruleId of entry.ruleIds) {
      out.ruleStats.push({
        ruleId,
        area: entry.area,
        scope: "code",
        status: entry.status as "completed" | "partial",
        targets: [{ unit: "files", examined: stats.parsed, reason: null }],
        findings: out.findings.filter((finding) => finding.ruleId === ruleId).length,
      });
    }
    out.coverage.push({
      area: "source:python:other-categories",
      scope: "code",
      status: "not_tested",
      ruleIds: [],
      ...coverageNote("python_other_categories"),
    });
    for (const [library, count] of libraries) {
      out.coverage.push({
        area: `source:orm:${label(library)}`,
        scope: "code",
        status: "partial",
        ruleIds: ["PG-SQL-006"],
        ...coverageNote("python_orm_unsupported", { library, count }),
      });
    }
    for (const [library, count] of processLibraries) {
      out.coverage.push({
        area: `source:process:${label(library)}`,
        scope: "code",
        status: "partial",
        ruleIds: ["PG-CMD-004"],
        ...coverageNote("python_process_unsupported", { library, count }),
      });
    }
    return out;
  } finally {
    runtime.dispose();
  }
}
