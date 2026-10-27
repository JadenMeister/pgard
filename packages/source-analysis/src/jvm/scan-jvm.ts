import type { Coverage, Finding, RuleStat } from "@pgard/findings";
import { createSourceFinding } from "../finding-factory.js";
import { JVM_RULE_IDS } from "../rules.js";
import {
  parseCoverage,
  parseTrackFiles,
  type LanguageTrackDetection,
  type TrackDeadline,
} from "../tree-sitter/language-track.js";
import { TREE_SITTER_LANGUAGE_LABEL, type TreeSitterLanguage } from "../tree-sitter/languages.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { readTextFile, type TrackedFile, type WalkResult } from "../walk.js";
import { analyzeJvmTree } from "./analyze-jvm.js";
import { analyzeMybatisXml } from "./mybatis-xml.js";

export const JVM_LANGUAGES: readonly TreeSitterLanguage[] = ["java", "kotlin"];

export interface JvmScanOptions {
  signal?: AbortSignal;
  deadline: TrackDeadline;
  /** True for a repository-relative path that `pgard.config.json` leaves out. */
  isExcluded?: (relativePath: string) => boolean;
}

export interface JvmScanOutput {
  findings: Finding[];
  coverage: Coverage[];
  ruleStats: RuleStat[];
  /** Java and Kotlin files that were parsed, plus mapper XML that was read. */
  analyzedPaths: string[];
  /** Mapper XML files that `exclude` left out (they declare a `<mapper>`). */
  excludedMapperPaths: string[];
  /** Files read as MyBatis mapper XML. */
  mapperFiles: number;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
  }
}

const METHOD =
  "tree-sitter syntax trees, intra-procedural source-to-sink tracking, SQL injection only (PG-SQL-005); no cross-file data flow and no other rule category yet";

/**
 * Parses and analyzes the Java and Kotlin files and the MyBatis mapper XML of a walk with the
 * SQL injection rule. Java and Kotlin files go through `parseTrackFiles`, so oversized,
 * unreadable and timed-out files and a grammar that fails its checksum make the area partial or
 * not tested, never "safe". Files are analyzed again on every scan (no result is cached).
 */
export async function scanJvm(
  walk: WalkResult,
  detection: LanguageTrackDetection,
  options: JvmScanOptions,
): Promise<JvmScanOutput> {
  const findings: Finding[] = [];
  const coverage: Coverage[] = [];
  const ruleStats: RuleStat[] = [];
  const analyzedPaths: string[] = [];
  const libraries = new Map<string, number>();
  const runtime = new TreeSitterRuntime();
  try {
    for (const language of JVM_LANGUAGES) {
      const files: readonly TrackedFile[] = walk.trackFiles[language];
      if (files.length === 0) continue;
      throwIfAborted(options.signal);
      const label = TREE_SITTER_LANGUAGE_LABEL[language];
      const own: Finding[] = [];
      const cappedFiles: string[] = [];
      const incompleteFiles: string[] = [];
      const formFiles = new Map<string, string[]>();
      let crashed = 0;
      const stats = await parseTrackFiles(
        runtime,
        language,
        files,
        { deadline: options.deadline },
        (file, outcome, source) => {
          throwIfAborted(options.signal);
          try {
            const analysis = analyzeJvmTree(
              outcome.tree.rootNode,
              source,
              file.relativePath,
              language === "kotlin" ? "kotlin" : "java",
            );
            analyzedPaths.push(file.relativePath);
            own.push(...analysis.findings.map(createSourceFinding));
            if (analysis.capped) cappedFiles.push(file.relativePath);
            if (analysis.incomplete) incompleteFiles.push(file.relativePath);
            for (const form of analysis.unsupportedForms) {
              formFiles.set(form, [...(formFiles.get(form) ?? []), file.relativePath]);
            }
            for (const library of analysis.unsupportedLibraries) {
              libraries.set(library, (libraries.get(library) ?? 0) + 1);
            }
          } catch {
            crashed += 1;
          }
        },
      );
      findings.push(...own);
      const base = parseCoverage(language, JVM_RULE_IDS, stats);
      const problems: string[] = [];
      if (cappedFiles.length > 0) {
        problems.push(
          `${cappedFiles.length} file(s) hit the per-file finding cap; further findings there are not listed`,
        );
      }
      if (incompleteFiles.length > 0) {
        problems.push(
          `${incompleteFiles.length} file(s) were nested too deeply to analyze in full`,
        );
      }
      for (const [form, paths] of formFiles) {
        problems.push(
          `${paths.length} file(s) have SQL calls inside ${form} bodies that are not followed (${[...new Set(paths)].slice(0, 3).join(", ")})`,
        );
      }
      if (crashed > 0) problems.push(`${crashed} file(s) could not be analyzed`);
      if (base.status === "not_tested") {
        coverage.push(base);
        continue;
      }
      const frameworks = detection.languages.find(
        (entry) => entry.language === language,
      )?.frameworks;
      const detected =
        frameworks !== undefined && frameworks.length > 0
          ? `; frameworks: ${frameworks.join(", ")}`
          : "";
      const lowerBound = detection.truncated ? "at least " : "";
      const note = [
        `${lowerBound}${files.length} ${label} file(s)${detected}; ${METHOD}.`,
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
      coverage.push(entry);
      for (const ruleId of entry.ruleIds) {
        ruleStats.push({
          ruleId,
          area: entry.area,
          scope: "code",
          status: entry.status as "completed" | "partial",
          targets: [{ unit: "files", examined: stats.parsed, reason: null }],
          findings: own.filter((finding) => finding.ruleId === ruleId).length,
        });
      }
    }

    // MyBatis mapper XML: any .xml file that declares <mapper>. Read here, analyzed as text.
    const excludedMapperPaths: string[] = [];
    let mapperFiles = 0;
    let unreadable = 0;
    let tooLarge = 0;
    let capped = 0;
    let unclosed = 0;
    const mapperFindings: Finding[] = [];
    // Any .xml file may be a mapper; only the ones that declare <mapper> are analyzed.
    for (const file of walk.xmlFiles) {
      throwIfAborted(options.signal);
      if (file.size > 1024 * 1024) {
        tooLarge += 1;
        continue;
      }
      const text = await readTextFile(file.absolutePath);
      if (text === null) {
        unreadable += 1;
        continue;
      }
      const analysis = analyzeMybatisXml(text, file.relativePath);
      if (!analysis.isMapper) continue;
      if (options.isExcluded?.(file.relativePath) === true) {
        excludedMapperPaths.push(file.relativePath);
        continue;
      }
      mapperFiles += 1;
      analyzedPaths.push(file.relativePath);
      mapperFindings.push(...analysis.findings.map(createSourceFinding));
      if (analysis.capped) capped += 1;
      if (analysis.incomplete) unclosed += 1;
    }
    findings.push(...mapperFindings);
    if (mapperFiles > 0) {
      const problems: string[] = [];
      if (capped > 0) {
        problems.push(
          `${capped} file(s) hit the per-file finding cap; further findings there are not listed`,
        );
      }
      if (unreadable > 0) problems.push(`${unreadable} XML file(s) were binary or unreadable`);
      if (tooLarge > 0) problems.push(`${tooLarge} XML file(s) over 1 MiB were not read`);
      if (walk.trackTruncated) problems.push("the file list reached its cap");
      if (unclosed > 0) {
        problems.push(
          `${unclosed} file(s) have a statement tag that is never closed; the rest of each was not read`,
        );
      }
      const entry: Coverage = {
        area: "source:mybatis",
        scope: "code",
        status: problems.length > 0 ? "partial" : "completed",
        ruleIds: JVM_RULE_IDS,
        note: `${mapperFiles} MyBatis mapper XML file(s); \${} substitutions in <select>, <insert>, <update> and <delete> (#{} is bound and not reported); text patterns, not an XML parser.${
          problems.length > 0 ? ` ${problems.join("; ")}.` : ""
        }`,
      };
      coverage.push(entry);
      for (const ruleId of entry.ruleIds) {
        ruleStats.push({
          ruleId,
          area: entry.area,
          scope: "code",
          status: entry.status as "completed" | "partial",
          targets: [{ unit: "files", examined: mapperFiles, reason: null }],
          findings: mapperFindings.filter((finding) => finding.ruleId === ruleId).length,
        });
      }
    } else if (unreadable + tooLarge > 0 && walk.trackFiles.java.length > 0) {
      coverage.push({
        area: "source:mybatis",
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: `${unreadable + tooLarge} XML file(s) were binary, unreadable or over 1 MiB, so MyBatis mapper XML in them was not checked.`,
      });
    }
    for (const [library, count] of libraries) {
      coverage.push({
        area: `source:orm:${library.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        scope: "code",
        status: "partial",
        ruleIds: [],
        note: `${library} detected in ${count} file(s); its raw SQL APIs are not supported, so queries made through them were not evaluated (not a safe result).`,
      });
    }
    return { findings, coverage, ruleStats, analyzedPaths, excludedMapperPaths, mapperFiles };
  } finally {
    runtime.dispose();
  }
}
