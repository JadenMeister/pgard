import type { Coverage, Finding, RuleStat } from "@pgard/findings";
import { createSourceFinding } from "../finding-factory.js";
import { JVM_RULE_IDS, MYBATIS_RULE_IDS, type SourceRuleId } from "../rules.js";
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
import {
  actuatorFinding,
  analyzeSpringConfig,
  MAX_SPRING_CONFIG_BYTES,
  type SpringConfigAnalysis,
} from "./spring-config.js";
import {
  analyzeJsp,
  analyzeThymeleaf,
  looksLikeThymeleaf,
  type ModelSource,
  type TemplateAnalysis,
} from "./templates.js";
import { TEMPLATE_ENGINES } from "./web-names.js";

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
  /** JSP and Thymeleaf template files that were read. */
  templateFiles: number;
}

const XSS_RULE_IDS: SourceRuleId[] = ["PG-XSS-004"];
const CONFIG_RULE_IDS: SourceRuleId[] = ["PG-COOKIE-001", "PG-CONF-001"];
/** Build files that name Spring Security as a dependency (text search, never executed). */
const SPRING_SECURITY_DEPENDENCY = /spring-security|spring-boot-starter-security|starter-oauth2/i;
const JSP_EXTENSIONS = new Set([".jsp", ".jspx", ".jspf", ".tag", ".tagx"]);
const extensionOf = (relativePath: string): string => {
  const dot = relativePath.lastIndexOf(".");
  return dot === -1 ? "" : relativePath.slice(dot).toLowerCase();
};

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("aborted");
  }
}

const METHOD =
  "tree-sitter syntax trees, intra-procedural source-to-sink tracking for SQL injection (PG-SQL-005), OS command execution (PG-CMD-003), path traversal (PG-PATH-002), XSS (PG-XSS-004; servlet and Spring responses here, JSP and Thymeleaf templates separately) and SSRF (PG-SSRF-002), and Spring Security and session configuration (PG-CSRF-001, PG-COOKIE-001, PG-CONF-001; the CSRF judgement reads one filter chain at a time, application.properties and application.yml are read separately); no cross-file data flow";

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
  const osLibraries = new Map<string, { kind: "process" | "file"; count: number }>();
  const templateLibraries = new Map<string, number>();
  const securityForms = new Map<string, string[]>();
  let usesSpringSecurity = false;
  /** Template models: the attributes that a controller fills from request input, by name. */
  const modelSources = new Map<string, ModelSource[]>();
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
      const errorFiles: string[] = [];
      const reflectionFiles: string[] = [];
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
            // `MISSING` nodes (tokens the parser inserted to recover) count like error nodes (#324).
            if (outcome.errorCount > 0 || outcome.missingCount > 0) {
              errorFiles.push(file.relativePath);
            }
            if (analysis.reflectionWeb) reflectionFiles.push(file.relativePath);
            if (analysis.usesSpringSecurity) usesSpringSecurity = true;
            for (const form of analysis.unsupportedSecurityForms) {
              securityForms.set(form, [...(securityForms.get(form) ?? []), file.relativePath]);
            }
            for (const attribute of analysis.modelAttributes) {
              if (attribute.tainted) {
                modelSources.set(attribute.name, [
                  ...(modelSources.get(attribute.name) ?? []),
                  { path: file.relativePath, line: attribute.line, views: attribute.views },
                ]);
              }
            }
            for (const library of analysis.unsupportedTemplateLibraries) {
              templateLibraries.set(library, (templateLibraries.get(library) ?? 0) + 1);
            }
            own.push(...analysis.findings.map(createSourceFinding));
            if (analysis.capped) cappedFiles.push(file.relativePath);
            if (analysis.incomplete) incompleteFiles.push(file.relativePath);
            for (const form of analysis.unsupportedForms) {
              formFiles.set(form, [...(formFiles.get(form) ?? []), file.relativePath]);
            }
            for (const library of analysis.unsupportedLibraries) {
              libraries.set(library, (libraries.get(library) ?? 0) + 1);
            }
            for (const library of analysis.unsupportedOsLibraries) {
              const known = osLibraries.get(library.label);
              osLibraries.set(library.label, {
                kind: library.kind,
                count: (known?.count ?? 0) + 1,
              });
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
          `${cappedFiles.length} file(s) hit the per-file finding cap (25 findings per rule per file); further findings there are not listed`,
        );
      }
      if (incompleteFiles.length > 0) {
        problems.push(
          `${incompleteFiles.length} file(s) were nested too deeply, or have loops that did not settle, to analyze in full`,
        );
      }
      for (const [form, paths] of formFiles) {
        problems.push(
          `${paths.length} file(s) have SQL, command, file-path, response-writing or URL calls inside ${form} bodies that are not followed (${[...new Set(paths)].slice(0, 3).join(", ")})`,
        );
      }
      for (const [form, paths] of securityForms) {
        problems.push(
          `${paths.length} file(s) build a Spring Security filter chain with ${form}, which is not followed, so what the chain does about CSRF and sessions is only partly known (${[...new Set(paths)].slice(0, 3).join(", ")})`,
        );
      }
      securityForms.clear();
      if (reflectionFiles.length > 0) {
        problems.push(
          `${reflectionFiles.length} file(s) call through reflection next to servlet, URL or HTTP client APIs; calls made that way are not followed (${reflectionFiles.slice(0, 3).join(", ")})`,
        );
      }
      if (errorFiles.length > 0) {
        problems.push(
          `${errorFiles.length} file(s) have syntax errors that the parser could not recover from cleanly (${errorFiles.slice(0, 3).join(", ")})`,
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
        ruleIds: MYBATIS_RULE_IDS,
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
    // Templates: JSP and Thymeleaf are read; other engines are reported as not analyzed.
    const templateFindings: Finding[] = [];
    let templatesRead = 0;
    let templateCapped = 0;
    let templateUnreadable = 0;
    let templateTooLarge = 0;
    let templateUnread = 0;
    const engineFiles = new Map<string, number>();
    // Templates are read only in a Java or Kotlin project: a Node or Python repository with
    // `.html`, `.mustache` or `.vm` files has none of this rule's concern.
    const jvmProject =
      walk.trackFiles.java.length + walk.trackFiles.kotlin.length > 0 ||
      walk.trackManifests.some(
        (manifest) => manifest.kind === "maven" || manifest.kind === "gradle",
      );
    for (const file of walk.templateFiles) {
      throwIfAborted(options.signal);
      const extension = extensionOf(file.relativePath);
      // JSP files are Java EE files whatever the project looks like; the rest need a JVM project.
      if (!jvmProject && !JSP_EXTENSIONS.has(extension)) continue;
      const engine = TEMPLATE_ENGINES[extension];
      if (engine !== undefined) {
        if (options.isExcluded?.(file.relativePath) === true) {
          excludedMapperPaths.push(file.relativePath);
          continue;
        }
        engineFiles.set(engine, (engineFiles.get(engine) ?? 0) + 1);
        continue;
      }
      const isJsp = JSP_EXTENSIONS.has(extension);
      // Any `.html` file may be a Thymeleaf template; big ones are generated pages and are not read.
      if (file.size > 1024 * 1024) {
        if (isJsp) templateTooLarge += 1;
        continue;
      }
      const text = await readTextFile(file.absolutePath);
      if (text === null) {
        if (isJsp) templateUnreadable += 1;
        continue;
      }
      let analysis: TemplateAnalysis | null = null;
      if (isJsp) {
        analysis = analyzeJsp(text, file.relativePath);
      } else if (looksLikeThymeleaf(text)) {
        analysis = analyzeThymeleaf(text, file.relativePath, modelSources);
      }
      if (analysis === null) continue;
      if (options.isExcluded?.(file.relativePath) === true) {
        excludedMapperPaths.push(file.relativePath);
        continue;
      }
      templatesRead += 1;
      analyzedPaths.push(file.relativePath);
      templateFindings.push(...analysis.findings.map(createSourceFinding));
      if (analysis.capped) templateCapped += 1;
      if (analysis.unread === true) templateUnread += 1;
    }
    findings.push(...templateFindings);
    if (templatesRead > 0 || templateUnreadable + templateTooLarge > 0) {
      const problems: string[] = [];
      if (templateCapped > 0) {
        problems.push(
          `${templateCapped} file(s) hit the per-file finding cap; further findings there are not listed`,
        );
      }
      if (templateUnreadable > 0)
        problems.push(`${templateUnreadable} JSP file(s) were binary or unreadable`);
      if (templateTooLarge > 0)
        problems.push(`${templateTooLarge} JSP file(s) over 1 MiB were not read`);
      if (templateUnread > 0) {
        problems.push(
          `${templateUnread} JSP file(s) use <jsp:scriptlet>, <jsp:expression> or <jsp:declaration>, which are not read`,
        );
      }
      if (walk.templatesTruncated) problems.push("the template file list reached its cap");
      const entry: Coverage = {
        area: "source:jvm-templates",
        scope: "code",
        status: problems.length > 0 ? "partial" : "completed",
        ruleIds: XSS_RULE_IDS,
        note: `${templatesRead} JSP and Thymeleaf template file(s); raw output (<%= %>, out.print, \${} in template text, th:utext, [( )], c:out escapeXml="false") is judged by where its value comes from; th:text, <c:out> and fn:escapeXml are escaped and not reported; a Thymeleaf model value is matched to a controller by attribute name only; patterns, not a template engine.${
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
          targets: [{ unit: "files", examined: templatesRead, reason: null }],
          findings: templateFindings.filter((finding) => finding.ruleId === ruleId).length,
        });
      }
    }
    // Spring Boot configuration files: read only in a Java or Kotlin project.
    const configFindings: Finding[] = [];
    const actuator: Array<{ path: string; line: number }> = [];
    let configRead = 0;
    let configCapped = 0;
    let configMalformed: string[] = [];
    let configOversized = 0;
    let configUnreadable = 0;
    if (jvmProject) {
      for (const file of walk.springConfigFiles) {
        throwIfAborted(options.signal);
        if (options.isExcluded?.(file.relativePath) === true) {
          excludedMapperPaths.push(file.relativePath);
          continue;
        }
        if (file.size > MAX_SPRING_CONFIG_BYTES) {
          configOversized += 1;
          continue;
        }
        const text = await readTextFile(file.absolutePath, MAX_SPRING_CONFIG_BYTES);
        if (text === null) {
          configUnreadable += 1;
          continue;
        }
        let analysis: SpringConfigAnalysis;
        try {
          analysis = analyzeSpringConfig(
            text,
            file.relativePath,
            /\.ya?ml$/i.test(file.relativePath) ? "yaml" : "properties",
          );
        } catch {
          configMalformed = [...configMalformed, file.relativePath];
          continue;
        }
        configRead += 1;
        analyzedPaths.push(file.relativePath);
        configFindings.push(...analysis.findings.map(createSourceFinding));
        if (analysis.capped) configCapped += 1;
        if (analysis.malformedLine !== null) {
          configMalformed = [...configMalformed, `${file.relativePath}:${analysis.malformedLine}`];
        }
        actuator.push(...analysis.actuatorExposure);
      }
      // Actuator exposure matters when nothing in the project shows Spring Security.
      if (actuator.length > 0) {
        let securityShown = usesSpringSecurity;
        for (const manifest of walk.trackManifests) {
          if (securityShown) break;
          if (manifest.kind !== "maven" && manifest.kind !== "gradle") continue;
          const manifestText = await readTextFile(manifest.absolutePath, 1024 * 1024);
          if (manifestText !== null && SPRING_SECURITY_DEPENDENCY.test(manifestText)) {
            securityShown = true;
          }
        }
        if (!securityShown) {
          configFindings.push(
            ...actuator.map((entry) =>
              createSourceFinding(
                actuatorFinding(
                  entry,
                  "no Spring Security import or dependency was found in the project",
                ),
              ),
            ),
          );
        }
      }
      findings.push(...configFindings);
      const problems: string[] = [];
      if (configCapped > 0) {
        problems.push(
          `${configCapped} file(s) hit the per-file finding cap; further findings there are not listed`,
        );
      }
      if (configMalformed.length > 0) {
        problems.push(
          `${configMalformed.length} file(s) have lines the reader could not parse (tabs for indentation, anchors, multi-line flow collections or malformed escapes), so the rest of each was read only in part (${configMalformed.slice(0, 3).join(", ")})`,
        );
      }
      if (configOversized > 0) {
        problems.push(
          `${configOversized} configuration file(s) over ${MAX_SPRING_CONFIG_BYTES / 1024} KiB were not read`,
        );
      }
      if (configUnreadable > 0) {
        problems.push(`${configUnreadable} configuration file(s) were binary or unreadable`);
      }
      if (walk.springConfigTruncated) problems.push("the configuration file list reached its cap");
      if (configRead + configOversized + configUnreadable > 0 || problems.length > 0) {
        const entry: Coverage = {
          area: "source:jvm-config",
          scope: "code",
          status: problems.length > 0 ? "partial" : "completed",
          ruleIds: CONFIG_RULE_IDS,
          note: `${configRead} Spring Boot configuration file(s) (application.properties, application-*.properties, application.yml, application-*.yml); server.servlet.session.cookie http-only and secure set to false, security debug logging and management.endpoints.web.exposure.include=* without Spring Security; values from a development profile or an environment variable with a default are reported low; a small YAML reader of block mappings, scalar lists and flow lists, not a full YAML parser.${
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
            targets: [{ unit: "files", examined: configRead, reason: null }],
            findings: configFindings.filter((finding) => finding.ruleId === ruleId).length,
          });
        }
      }
    }
    const engines = new Map<string, number>(engineFiles);
    for (const [library, count] of templateLibraries) {
      engines.set(library, Math.max(engines.get(library) ?? 0, count));
    }
    for (const [engine, count] of engines) {
      coverage.push({
        area: `source:template:${engine.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        scope: "code",
        status: "partial",
        ruleIds: XSS_RULE_IDS,
        note: `${engine} detected in ${count} file(s); its templates are not supported, so output written through them was not evaluated for XSS (not a safe result).`,
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
    for (const [library, { kind, count }] of osLibraries) {
      coverage.push({
        area: `source:${kind}:${library.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        scope: "code",
        status: "partial",
        ruleIds: kind === "process" ? ["PG-CMD-003"] : ["PG-PATH-002"],
        note: `${library} detected in ${count} file(s); its ${
          kind === "process" ? "process-running" : "file-access"
        } APIs are not supported, so ${
          kind === "process" ? "commands run" : "paths opened"
        } through it were not evaluated (not a safe result).`,
      });
    }
    return {
      findings,
      coverage,
      ruleStats,
      analyzedPaths,
      excludedMapperPaths,
      mapperFiles,
      templateFiles: templatesRead,
    };
  } finally {
    runtime.dispose();
  }
}
