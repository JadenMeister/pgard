import type { Finding } from "./contract.js";
import { readFindingList } from "./read-result.js";

/**
 * What an incremental scan needs from the scan it is based on, beyond the result itself. It is
 * written next to the stored result (never into the JSON a user sees) and is only ever trusted
 * to skip work: every use is checked against the current files, and anything unreadable or
 * unexpected makes the next scan a full one.
 *
 * It holds no source text and no secret value: per file, the content hash, the findings (already
 * redacted, the same text the result stores) and the small facts the project-wide checks need.
 */
export const INCREMENTAL_STATE_FORMAT = 1;
/** Entries kept at most; a larger project stores no state and every scan is a full one. */
export const INCREMENTAL_STATE_MAX_FILES = 20_000;

export type CachedSourceLanguage = "javascript" | "typescript" | "vue" | "go";
export const CACHED_SOURCE_LANGUAGES: readonly CachedSourceLanguage[] = [
  "javascript",
  "typescript",
  "vue",
  "go",
];

/** The result of analyzing one source file, keyed by repository-relative path and content hash. */
export interface CachedSourceFile {
  path: string;
  language: CachedSourceLanguage;
  /** SHA-256 (hex) of the file text that was analyzed. */
  hash: string;
  /** The file's own findings, before scan-core normalizes them. */
  findings: Finding[];
  /** The JavaScript/TypeScript/Vue facts the project-wide checks read (opaque here). */
  facts: Record<string, unknown> | null;
  /** Go import paths (used to detect unsupported ORMs). */
  goImports: string[];
  hasJsx: boolean;
  hasParseErrors: boolean;
  /** The per-file finding cap was reached. */
  capped: boolean;
}

export interface IncrementalState {
  format: typeof INCREMENTAL_STATE_FORMAT;
  /** Hash of everything that decides what an analyzer reports for the same file text. */
  analysisKey: string;
  /** Hash of the analyzer source (`ANALYZER_HASH`): changes whenever analysis code changes. */
  analyzerHash: string;
  /** Hash of `pgard.config.json` as read, or null when there was none. */
  configHash: string | null;
  /** Analyzed source files; null when the code scope did not run. */
  code: CachedSourceFile[] | null;
}

type Obj = Record<string, unknown>;

function isObject(value: unknown): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") return null;
    out.push(item);
  }
  return out;
}

function readCachedFile(value: unknown): CachedSourceFile | null {
  if (!isObject(value)) return null;
  const { path, language, hash, findings, facts, goImports, hasJsx, hasParseErrors, capped } =
    value;
  if (typeof path !== "string" || typeof hash !== "string") return null;
  if (!CACHED_SOURCE_LANGUAGES.includes(language as CachedSourceLanguage)) return null;
  if (typeof hasJsx !== "boolean" || typeof hasParseErrors !== "boolean") return null;
  if (typeof capped !== "boolean") return null;
  if (facts !== null && !isObject(facts)) return null;
  const imports = stringList(goImports);
  const readFindings = readFindingList(findings);
  if (imports === null || readFindings === null) return null;
  return {
    path,
    language: language as CachedSourceLanguage,
    hash,
    findings: readFindings,
    facts: facts === null ? null : (JSON.parse(JSON.stringify(facts)) as Obj),
    goImports: imports,
    hasJsx,
    hasParseErrors,
    capped,
  };
}

/** Validates a stored state; `null` for anything that is not a state this PGARD wrote. Never throws. */
export function readIncrementalState(input: unknown): IncrementalState | null {
  try {
    if (!isObject(input) || input.format !== INCREMENTAL_STATE_FORMAT) return null;
    if (typeof input.analysisKey !== "string" || typeof input.analyzerHash !== "string") {
      return null;
    }
    if (input.configHash !== null && typeof input.configHash !== "string") return null;
    let code: CachedSourceFile[] | null = null;
    if (input.code !== null) {
      if (!Array.isArray(input.code) || input.code.length > INCREMENTAL_STATE_MAX_FILES) {
        return null;
      }
      code = [];
      for (const entry of input.code) {
        const file = readCachedFile(entry);
        if (file === null) return null;
        code.push(file);
      }
    }
    return {
      format: INCREMENTAL_STATE_FORMAT,
      analysisKey: input.analysisKey,
      analyzerHash: input.analyzerHash,
      configHash: input.configHash,
      code,
    };
  } catch {
    return null;
  }
}
