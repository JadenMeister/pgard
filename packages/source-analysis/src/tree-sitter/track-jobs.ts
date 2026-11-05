import { analyzeJvmTree, type JvmAnalysis } from "../jvm/analyze-jvm.js";
import { analyzeMybatisXml, type MybatisAnalysis } from "../jvm/mybatis-xml.js";
import { analyzeSpringConfig, type SpringConfigAnalysis } from "../jvm/spring-config.js";
import {
  analyzeJsp,
  analyzeThymeleaf,
  looksLikeThymeleaf,
  type ModelSource,
  type TemplateAnalysis,
} from "../jvm/templates.js";
import {
  classifyAnalysisError,
  createJobRunner,
  type JobOutcome,
  type JobRunner,
} from "../job-worker.js";
import { analyzePhpTree, type PhpFileAnalysis } from "../php/analyze-php.js";
import { analyzePythonTree, type PythonAnalysis } from "../python/analyze-python.js";
import { detectPhpNamespaceFrameworks, type Framework } from "./detect-frameworks.js";
import type { TreeSitterLanguage } from "./languages.js";
import { TreeSitterRuntime } from "./runtime.js";

/**
 * One unit of work of a tree-sitter track: a file's parse and rule analysis, or the text analysis
 * of a MyBatis mapper, a template or a Spring configuration file. A job carries everything it
 * needs (the text and the per-track context: Django, the template model attributes), so it runs
 * the same in the calling thread and in a worker thread, where `track-worker.ts` runs it under the
 * hard per-file limit of `job-worker.ts`. The grammars load, with their pinned checksum verified
 * by `TreeSitterRuntime`, in whichever thread runs the job: there is no other way to load one.
 */
export type TrackJob =
  | {
      kind: "tree";
      language: TreeSitterLanguage;
      source: string;
      relativePath: string;
      /** Parse limits (the analysis that follows has the job's hard limit instead). */
      timeoutMs: number;
      maxBytes: number;
      /** Python: the project's manifests name Django. */
      django: boolean;
    }
  | { kind: "mybatis"; text: string; relativePath: string }
  | {
      kind: "template";
      /** JSP files are always templates; other files are read only when they look like Thymeleaf. */
      isJsp: boolean;
      text: string;
      relativePath: string;
      /** Thymeleaf: the controller model attributes found in the Java and Kotlin files. */
      model: Array<[string, ModelSource[]]>;
    }
  | {
      kind: "spring-config";
      text: string;
      relativePath: string;
      format: "properties" | "yaml";
    };

/** What the rule analysis of a parsed file reports; a file-level crash is `analysis: null`. */
export type TreeAnalysis = JvmAnalysis | PythonAnalysis | PhpFileAnalysis;

export type TreeJobOutcome =
  | {
      status: "parsed";
      errorCount: number;
      missingCount: number;
      /** Null when the analysis threw: the file counts as parsed but not analyzed. */
      analysis: TreeAnalysis | null;
      /** PHP: frameworks named by the file's namespaces. */
      namespaceFrameworks: Framework[];
    }
  | { status: "too_large" }
  | { status: "timeout" }
  | { status: "unavailable"; reason: string }
  | { status: "failed" };

export type TrackResult =
  | { kind: "tree"; outcome: TreeJobOutcome }
  | { kind: "mybatis"; analysis: MybatisAnalysis }
  /** `analysis` is null when the file is not a template (a plain HTML file). */
  | { kind: "template"; analysis: TemplateAnalysis | null }
  | { kind: "spring-config"; analysis: SpringConfigAnalysis };

export interface TrackExecutor {
  run(
    job: TrackJob,
    limitMs: number,
    signal: AbortSignal | undefined,
  ): Promise<JobOutcome<TrackResult>>;
  /** Ends the scan's use of the executor (a worker goes back to the idle slot). */
  release(): void;
}

async function runTreeJob(
  job: Extract<TrackJob, { kind: "tree" }>,
  runtime: TreeSitterRuntime,
): Promise<TreeJobOutcome> {
  const parsed = await runtime.parse(job.language, job.source, {
    timeoutMs: job.timeoutMs,
    maxBytes: job.maxBytes,
  });
  switch (parsed.status) {
    case "too_large":
      return { status: "too_large" };
    case "timeout":
      return { status: "timeout" };
    case "failed":
      return { status: "failed" };
    case "unavailable":
      return { status: "unavailable", reason: parsed.reason };
    case "parsed":
      break;
  }
  try {
    const root = parsed.tree.rootNode;
    let analysis: TreeAnalysis | null = null;
    let namespaceFrameworks: Framework[] = [];
    try {
      if (job.language === "java" || job.language === "kotlin") {
        analysis = analyzeJvmTree(root, job.source, job.relativePath, job.language);
      } else if (job.language === "python") {
        analysis = analyzePythonTree(root, job.source, job.relativePath, { django: job.django });
      } else {
        analysis = analyzePhpTree(root, job.source, job.relativePath);
        namespaceFrameworks = detectPhpNamespaceFrameworks(job.source);
      }
    } catch {
      analysis = null;
    }
    return {
      status: "parsed",
      errorCount: parsed.errorCount,
      missingCount: parsed.missingCount,
      analysis,
      namespaceFrameworks,
    };
  } finally {
    parsed.dispose();
  }
}

/** Runs one job in the calling thread. A thrown error is the caller's to classify. */
export async function runTrackJob(job: TrackJob, runtime: TreeSitterRuntime): Promise<TrackResult> {
  switch (job.kind) {
    case "tree":
      return { kind: "tree", outcome: await runTreeJob(job, runtime) };
    case "mybatis":
      return { kind: "mybatis", analysis: analyzeMybatisXml(job.text, job.relativePath) };
    case "template": {
      if (job.isJsp) {
        return { kind: "template", analysis: analyzeJsp(job.text, job.relativePath) };
      }
      if (!looksLikeThymeleaf(job.text)) return { kind: "template", analysis: null };
      return {
        kind: "template",
        analysis: analyzeThymeleaf(job.text, job.relativePath, new Map(job.model)),
      };
    }
    case "spring-config":
      return {
        kind: "spring-config",
        analysis: analyzeSpringConfig(job.text, job.relativePath, job.format),
      };
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

/** The shape the scan reads from a worker's answer; anything else is a worker failure. */
export function isTrackResult(value: unknown): value is TrackResult {
  if (!isObject(value)) return false;
  if (value.kind === "tree") {
    const outcome = value.outcome;
    if (!isObject(outcome)) return false;
    if (outcome.status === "parsed") {
      return (
        typeof outcome.errorCount === "number" &&
        typeof outcome.missingCount === "number" &&
        (outcome.analysis === null ||
          (isObject(outcome.analysis) && Array.isArray(outcome.analysis.findings))) &&
        Array.isArray(outcome.namespaceFrameworks)
      );
    }
    if (outcome.status === "unavailable") return typeof outcome.reason === "string";
    return (
      outcome.status === "too_large" || outcome.status === "timeout" || outcome.status === "failed"
    );
  }
  if (value.kind === "template") {
    return (
      value.analysis === null ||
      (isObject(value.analysis) && Array.isArray(value.analysis.findings))
    );
  }
  if (value.kind === "mybatis" || value.kind === "spring-config") {
    return isObject(value.analysis) && Array.isArray(value.analysis.findings);
  }
  return false;
}

/**
 * Runs the jobs in the calling thread (no hard limit; used when there is no worker, as the test
 * runner has none). The runtime starts on the first tree job and is freed by `release`.
 */
export function createInlineTrackExecutor(
  makeRuntime: () => TreeSitterRuntime = () => new TreeSitterRuntime(),
): TrackExecutor {
  let runtime: TreeSitterRuntime | null = null;
  return {
    run: async (job) => {
      try {
        runtime ??= makeRuntime();
        return { kind: "done", value: await runTrackJob(job, runtime) };
      } catch (error) {
        return { kind: classifyAnalysisError(error) };
      }
    },
    release: () => {
      runtime?.dispose();
      runtime = null;
    },
  };
}

/** Runs each job in a worker thread under a hard deadline (see `job-worker.ts`). */
export function createWorkerTrackExecutor(url: URL): TrackExecutor {
  const runner: JobRunner<{ job: TrackJob }, TrackResult> = createJobRunner(
    url,
    "result",
    isTrackResult,
  );
  return {
    run: (job, limitMs, signal) => runner.run({ job }, limitMs, signal),
    release: () => runner.release(),
  };
}

/** The worker entry next to the built modules; null when running from TypeScript source. */
export function trackWorkerFor(analysisWorker: URL | null): URL | null {
  return analysisWorker === null ? null : new URL("./track-worker.js", analysisWorker);
}
