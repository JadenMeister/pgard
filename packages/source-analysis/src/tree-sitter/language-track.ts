import type { Coverage } from "@pgard/findings";
import { readTextFile, type TrackedFile, type WalkResult } from "../walk.js";
import {
  detectFrameworks,
  FRAMEWORK_LANGUAGES,
  type Framework,
  type ManifestIssue,
} from "./detect-frameworks.js";
import {
  TREE_SITTER_LANGUAGE_LABEL,
  TREE_SITTER_LANGUAGES,
  type TreeSitterLanguage,
} from "./languages.js";
import {
  DEFAULT_PARSE_LIMITS,
  type ParseOptions,
  type ParseOutcome,
  type TreeSitterRuntime,
} from "./runtime.js";

/** Wall-clock budget for parsing the whole tree-sitter track (all languages) in one scan. */
export const MAX_TRACK_PARSE_MS = 60_000;
/** Parse timeouts tolerated per language before the remaining files of it are not parsed. */
export const MAX_PARSE_TIMEOUTS_PER_LANGUAGE = 3;

export const NO_RULES_NOTE = "detected, no rules yet";
const MAX_LISTED = 5;

export interface DetectedLanguage {
  language: TreeSitterLanguage;
  files: number;
  frameworks: Framework[];
}

export interface LanguageTrackDetection {
  languages: DetectedLanguage[];
  manifestIssues: ManifestIssue[];
  /** A file list reached its cap, so the counts are lower bounds. */
  truncated: boolean;
}

/**
 * Detects Java, Kotlin, Python and PHP files and their frameworks. Read-only: manifests are only
 * read as text. No grammar is loaded here.
 */
export async function detectLanguageTrack(walk: WalkResult): Promise<LanguageTrackDetection> {
  const present = TREE_SITTER_LANGUAGES.filter((language) => walk.trackFiles[language].length > 0);
  const { frameworks, issues } =
    present.length > 0
      ? await detectFrameworks(walk.trackManifests)
      : { frameworks: [], issues: [] as ManifestIssue[] };
  return {
    languages: present.map((language) => ({
      language,
      files: walk.trackFiles[language].length,
      frameworks: [
        ...new Set(
          frameworks
            .filter((entry) => FRAMEWORK_LANGUAGES[entry.framework].includes(language))
            .map((entry) => entry.framework),
        ),
      ],
    })),
    manifestIssues: issues,
    truncated: walk.trackTruncated,
  };
}

function listQuoted(items: readonly string[]): string {
  const listed = items
    .slice(0, MAX_LISTED)
    .map((item) => JSON.stringify(item))
    .join(", ");
  return items.length > MAX_LISTED ? `${listed} and ${items.length - MAX_LISTED} more` : listed;
}

/**
 * Coverage for the detected languages: `not_tested` with "detected, no rules yet" until rules for
 * the language exist. Manifests that could not be read or were unsafe make a `partial` entry.
 */
export function languageTrackCoverage(detection: LanguageTrackDetection): Coverage[] {
  const coverage: Coverage[] = detection.languages.map((entry) => {
    const label = TREE_SITTER_LANGUAGE_LABEL[entry.language];
    const frameworks =
      entry.frameworks.length > 0 ? `; frameworks: ${entry.frameworks.join(", ")}` : "";
    const lowerBound = detection.truncated ? "at least " : "";
    return {
      area: `source:${entry.language}`,
      scope: "code",
      status: "not_tested",
      ruleIds: [],
      note: `${label} ${NO_RULES_NOTE} (${lowerBound}${entry.files} file(s)${frameworks}). These files were not analyzed and are not a safe result.`,
    };
  });
  if (detection.manifestIssues.length > 0) {
    coverage.push({
      area: "source:manifests",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: `Framework detection is incomplete: ${describeManifestIssues(detection.manifestIssues)}.`,
    });
  }
  return coverage;
}

function describeManifestIssues(issues: readonly ManifestIssue[]): string {
  const byReason = (reason: ManifestIssue["reason"]) =>
    issues.filter((issue) => issue.reason === reason).map((issue) => issue.path);
  const parts: string[] = [];
  const unreadable = byReason("unreadable_or_too_large");
  if (unreadable.length > 0) {
    parts.push(`${listQuoted(unreadable)} over 1 MiB, binary or unreadable (skipped)`);
  }
  const unsafe = byReason("unsafe_xml");
  if (unsafe.length > 0) {
    parts.push(`${listQuoted(unsafe)} declare a DTD or entities (ignored, not expanded)`);
  }
  const invalid = byReason("invalid_json");
  if (invalid.length > 0) parts.push(`${listQuoted(invalid)} are not valid JSON`);
  const cut = byReason("cut");
  if (cut.length > 0) parts.push(`${listQuoted(cut)} were read only in part`);
  return parts.join("; ");
}

/** Shared by every `parseTrackFiles` call of one scan: the scan-wide parse deadline. */
export interface TrackDeadline {
  /** Absolute time (same clock as `now`) after which no further file is parsed. */
  endsAt: number;
  totalMs: number;
  now: () => number;
}

export function createTrackDeadline(
  totalMs = MAX_TRACK_PARSE_MS,
  now: () => number = () => performance.now(),
): TrackDeadline {
  return { endsAt: now() + totalMs, totalMs, now };
}

export interface ParseStats {
  files: number;
  /** Files not parsed because the scan-wide deadline or the timeout cap was reached. */
  notParsed: number;
  stoppedBy: "deadline" | "timeouts" | null;
  totalBudgetMs: number | null;
  maxTimeouts: number | null;
  parsed: number;
  tooLarge: string[];
  timedOut: string[];
  unreadable: string[];
  failed: string[];
  /** Why the grammar could not be used (checksum mismatch, unreadable); no file was parsed. */
  grammarUnavailable: string | null;
  /** Files that parsed with at least one `ERROR` node. They are still analyzed. */
  filesWithSyntaxErrors: number;
  errorNodes: number;
}

export function emptyParseStats(): ParseStats {
  return {
    files: 0,
    notParsed: 0,
    stoppedBy: null,
    totalBudgetMs: null,
    maxTimeouts: null,
    parsed: 0,
    tooLarge: [],
    timedOut: [],
    unreadable: [],
    failed: [],
    grammarUnavailable: null,
    filesWithSyntaxErrors: 0,
    errorNodes: 0,
  };
}

/**
 * Reads and parses the files of one language with the size and time limits, calling `visit` for
 * each parsed tree (the tree is freed afterwards). The grammar loads on the first file, so
 * calling this with an empty list loads nothing. Oversized files are rejected from the `lstat`
 * size without being read.
 */
export async function parseTrackFiles(
  runtime: TreeSitterRuntime,
  language: TreeSitterLanguage,
  files: readonly TrackedFile[],
  options: ParseOptions & {
    /** Scan-wide deadline shared across languages. Omit for no total limit. */
    deadline?: TrackDeadline;
    maxTimeouts?: number;
  } = {},
  visit?: (file: TrackedFile, outcome: Extract<ParseOutcome, { status: "parsed" }>) => void,
): Promise<ParseStats> {
  const maxBytes = options.maxBytes ?? DEFAULT_PARSE_LIMITS.maxBytes;
  const maxTimeouts = options.maxTimeouts ?? MAX_PARSE_TIMEOUTS_PER_LANGUAGE;
  const deadline = options.deadline;
  const stats = emptyParseStats();
  stats.maxTimeouts = maxTimeouts;
  if (deadline) stats.totalBudgetMs = deadline.totalMs;
  for (const [index, file] of files.entries()) {
    if (stats.stoppedBy === null && deadline && deadline.now() >= deadline.endsAt) {
      stats.stoppedBy = "deadline";
    } else if (stats.stoppedBy === null && stats.timedOut.length >= maxTimeouts) {
      stats.stoppedBy = "timeouts";
    }
    if (stats.stoppedBy !== null) {
      stats.notParsed = files.length - index;
      stats.files += stats.notParsed;
      break;
    }
    stats.files += 1;
    if (file.size > maxBytes) {
      stats.tooLarge.push(file.relativePath);
      continue;
    }
    const source = await readTextFile(file.absolutePath, maxBytes);
    if (source === null) {
      stats.unreadable.push(file.relativePath);
      continue;
    }
    // A single parse never runs past the scan-wide deadline either.
    const remaining = deadline ? Math.max(1, deadline.endsAt - deadline.now()) : Infinity;
    const outcome = await runtime.parse(language, source, {
      ...options,
      timeoutMs: Math.min(options.timeoutMs ?? DEFAULT_PARSE_LIMITS.timeoutMs, remaining),
    });
    switch (outcome.status) {
      case "too_large":
        stats.tooLarge.push(file.relativePath);
        break;
      case "timeout":
        stats.timedOut.push(file.relativePath);
        break;
      case "failed":
        stats.failed.push(file.relativePath);
        break;
      case "unavailable":
        // Every remaining file would fail the same way; stop instead of retrying each one.
        stats.grammarUnavailable = outcome.reason;
        stats.notParsed = files.length - index;
        stats.files += files.length - index - 1;
        return stats;
      case "parsed":
        stats.parsed += 1;
        if (outcome.errorCount > 0) {
          stats.filesWithSyntaxErrors += 1;
          stats.errorNodes += outcome.errorCount;
        }
        try {
          visit?.(file, outcome);
        } finally {
          outcome.dispose();
        }
        break;
    }
  }
  return stats;
}

/**
 * Coverage after parsing and running rules over one language. Any file that was too large, timed
 * out, was unreadable or failed to parse makes the area `partial` and is named in the note: a
 * file that was not parsed is never reported as safe. Syntax errors alone keep it `completed`
 * (the parser recovers), but are counted in the note.
 */
export function parseCoverage(
  language: TreeSitterLanguage,
  ruleIds: string[],
  stats: ParseStats,
  limits: Partial<{ maxBytes: number; timeoutMs: number }> = {},
): Coverage {
  const maxBytes = limits.maxBytes ?? DEFAULT_PARSE_LIMITS.maxBytes;
  const timeoutMs = limits.timeoutMs ?? DEFAULT_PARSE_LIMITS.timeoutMs;
  const label = TREE_SITTER_LANGUAGE_LABEL[language];
  if (stats.grammarUnavailable !== null) {
    return {
      area: `source:${language}`,
      scope: "code",
      status: "not_tested",
      ruleIds: [],
      note: `${label}: the parser grammar was not used (${stats.grammarUnavailable}), so no ${label} file was analyzed. This is not a safe result.`,
    };
  }
  const problems: string[] = [];
  if (stats.tooLarge.length > 0) {
    problems.push(
      `${stats.tooLarge.length} file(s) over ${Math.round(maxBytes / 1024)} KiB were not parsed (${listQuoted(stats.tooLarge)})`,
    );
  }
  if (stats.timedOut.length > 0) {
    problems.push(
      `${stats.timedOut.length} file(s) hit the parse budget (${timeoutMs} ms per file) or the scan deadline (${listQuoted(stats.timedOut)})`,
    );
  }
  if (stats.unreadable.length > 0) {
    problems.push(`${stats.unreadable.length} file(s) were binary or unreadable`);
  }
  if (stats.failed.length > 0) {
    problems.push(
      `${stats.failed.length} file(s) could not be parsed (${listQuoted(stats.failed)})`,
    );
  }
  if (stats.stoppedBy !== null) {
    problems.push(
      stats.stoppedBy === "deadline"
        ? `parsing stopped at the ${Math.round((stats.totalBudgetMs ?? MAX_TRACK_PARSE_MS) / 1000)} s scan-wide budget; ${stats.notParsed} of ${stats.files} file(s) were not parsed`
        : `parsing stopped after ${stats.maxTimeouts ?? MAX_PARSE_TIMEOUTS_PER_LANGUAGE} timeouts; ${stats.notParsed} of ${stats.files} file(s) were not parsed`,
    );
  }
  const notes: string[] = [];
  if (problems.length > 0) {
    notes.push(
      `${label}: ${problems.join("; ")}. Those files were not analyzed and are not a safe result.`,
    );
  }
  if (stats.filesWithSyntaxErrors > 0) {
    notes.push(
      `${stats.filesWithSyntaxErrors} file(s) had syntax errors (${stats.errorNodes} error node(s)) and may be partially analyzed.`,
    );
  }
  return {
    area: `source:${language}`,
    scope: "code",
    status: problems.length > 0 ? "partial" : "completed",
    ruleIds,
    note: notes.length > 0 ? notes.join(" ") : null,
  };
}
