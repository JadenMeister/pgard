/**
 * Small path glob matcher for the project configuration file (`pgard.config.json`).
 *
 * Why hand-written: patterns come from the scanned repository, which is untrusted input. No
 * regular expression is ever built from a pattern, so there is no pattern that can make a regex
 * engine backtrack exponentially (ReDoS), and nothing needs escaping.
 *
 * ## Syntax
 * - Patterns are repository-relative POSIX paths. Case-sensitive.
 * - `*` matches any run of characters inside one path segment (never `/`), `?` matches one
 *   character, `**` as a whole segment matches zero or more segments. Dot files are matched.
 * - A pattern with no `/` matches at any depth (`*.gen.ts` = `**` + `/*.gen.ts`).
 * - A pattern also matches everything below a matching directory (`legacy` = `legacy` + `/**`),
 *   and a trailing `/` is ignored.
 * - Rejected: absolute paths, drive letters, `.` and `..` segments, empty segments, backslashes,
 *   control characters, `[ ] { }` and a leading `!` (no classes, alternation or negation).
 *
 * ## Complexity
 * Matching is dynamic programming, never backtracking. For a pattern of `p` segments and a path
 * of `s` segments, the segment table has p x s cells and each cell compares one pattern segment
 * with one path segment in O(len(pattern segment) x len(path segment)) by a second table. The
 * total work is therefore bounded by O(len(pattern) x len(path)): linear in the path length for a
 * pattern of the capped length (200), with no input that makes it exponential. Paths longer than
 * MAX_PATH_LENGTH never match (the file stays analyzed, never silently skipped).
 */

export const MAX_GLOB_LENGTH = 200;
export const MAX_GLOB_SEGMENTS = 32;
/** `*` per segment: each one adds a table row per name character, so they are capped. */
export const MAX_STARS_PER_SEGMENT = 10;
/** Longer paths never match a pattern, which keeps the per-file work bounded. */
export const MAX_PATH_LENGTH = 4096;

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
/**
 * Format characters (bidi controls, zero-width, joiners...), lone surrogates, C1 controls, line and
 * paragraph separators, the combining grapheme joiner and the Hangul fillers (which render as
 * blanks): invisible or ambiguous.
 */
const INVISIBLE = /[\p{Cf}\p{Cs}\p{Zl}\p{Zp}\u0080-\u009f\u034f\u115f\u1160\u3164\uffa0]/u;
export const INVISIBLE_CHARACTERS = INVISIBLE;

/** Why a pattern is not acceptable, or `null` when it is. */
export function globProblem(pattern: unknown): string | null {
  if (typeof pattern !== "string") return "must be a string";
  if (pattern.length === 0) return "must not be empty";
  if (pattern.length > MAX_GLOB_LENGTH) return `must be at most ${MAX_GLOB_LENGTH} characters`;
  if (CONTROL.test(pattern)) return "must not contain control characters";
  if (INVISIBLE.test(pattern)) {
    return "must not contain bidirectional, zero-width or other format characters, or lone surrogates";
  }
  if (pattern.includes("\\")) return "must use / as the separator (no backslashes)";
  if (/[[\]{}]/.test(pattern)) return "must not use [ ] { } (only *, ** and ? are supported)";
  if (pattern.startsWith("!")) return "must not start with ! (negation is not supported)";
  if (pattern.startsWith("/") || /^[A-Za-z]:/.test(pattern)) {
    return "must be relative to the repository root, not an absolute path";
  }
  const trimmed = pattern.endsWith("/") ? pattern.slice(0, -1) : pattern;
  const segments = trimmed.split("/");
  if (segments.length > MAX_GLOB_SEGMENTS) return `must have at most ${MAX_GLOB_SEGMENTS} segments`;
  for (const segment of segments) {
    if (segment === "") return "must not contain empty path segments";
    if (segment === "..") return 'must not contain ".."';
    if (segment === ".") return 'must not contain "."';
    if (segment.includes("**") && segment !== "**") return "must use ** as a whole path segment";
    if (segment.split("*").length - 1 > MAX_STARS_PER_SEGMENT) {
      return `must have at most ${MAX_STARS_PER_SEGMENT} * in one path segment`;
    }
  }
  return null;
}

export interface CompiledGlob {
  readonly source: string;
  /** Normalized segments; `**` is a whole segment, consecutive ones are collapsed. */
  readonly segments: readonly string[];
}

/** Compiles a pattern that passed `globProblem`; throws for one that did not. */
export function compileGlob(pattern: string): CompiledGlob {
  const problem = globProblem(pattern);
  if (problem !== null) throw new Error(`Invalid glob: ${problem}`);
  const trimmed = pattern.endsWith("/") ? pattern.slice(0, -1) : pattern;
  let segments = trimmed.split("/");
  if (segments.length === 1) segments = ["**", ...segments];
  if (segments[segments.length - 1] !== "**") segments.push("**");
  const collapsed = segments.filter(
    (segment, index) => segment !== "**" || segments[index - 1] !== "**",
  );
  return { source: pattern, segments: collapsed };
}

// Rows are allocated once: matching runs synchronously, so sharing them is safe, and a scan of
// 20 000 files does not allocate a table per file and segment.
const ROW_SIZE = MAX_PATH_LENGTH + 2;
const charRows: [Uint8Array, Uint8Array] = [new Uint8Array(ROW_SIZE), new Uint8Array(ROW_SIZE)];
const segmentRows: [Uint8Array, Uint8Array] = [new Uint8Array(ROW_SIZE), new Uint8Array(ROW_SIZE)];

/** Table cells filled since the module loaded; a `PathMatcher` reads the difference per match. */
let workDone = 0;

/** `*` and `?` inside one segment, by dynamic programming over (pattern chars x name chars). */
function segmentMatches(pattern: string, name: string): boolean {
  if (!pattern.includes("*") && !pattern.includes("?")) return pattern === name;
  // Cheap rejection before the table: the literal text before the first wildcard and after the
  // last one must match exactly (`*a*a*b` against a name that does not end in `b`).
  const first = pattern.search(/[*?]/);
  const last = Math.max(pattern.lastIndexOf("*"), pattern.lastIndexOf("?"));
  if (!name.startsWith(pattern.slice(0, first))) return false;
  const suffix = pattern.slice(last + 1);
  if (name.length < first + suffix.length || !name.endsWith(suffix)) return false;
  workDone += pattern.length * (name.length + 1);
  let row = charRows[0];
  let next = charRows[1];
  row.fill(0, 0, name.length + 1);
  row[0] = 1;
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern.charAt(i);
    next.fill(0, 0, name.length + 1);
    if (char === "*") {
      next[0] = row[0] as number;
      for (let j = 1; j <= name.length; j += 1) {
        next[j] = (next[j - 1] as number) | (row[j] as number);
      }
    } else {
      for (let j = 1; j <= name.length; j += 1) {
        if (row[j - 1] === 1 && (char === "?" || char === name.charAt(j - 1))) next[j] = 1;
      }
    }
    [row, next] = [next, row];
  }
  return row[name.length] === 1;
}

/** Whether `filePath` (repository-relative, POSIX) is matched by the compiled glob. */
export function globMatches(glob: CompiledGlob, filePath: string): boolean {
  if (filePath.length === 0 || filePath.length > MAX_PATH_LENGTH) return false;
  const names = filePath.split("/");
  workDone += glob.segments.length * (names.length + 1);
  let reach = segmentRows[0];
  let next = segmentRows[1];
  reach.fill(0, 0, names.length + 1);
  reach[0] = 1;
  for (const segment of glob.segments) {
    next.fill(0, 0, names.length + 1);
    if (segment === "**") {
      next[0] = reach[0] as number;
      for (let j = 1; j <= names.length; j += 1) {
        next[j] = (next[j - 1] as number) | (reach[j] as number);
      }
    } else {
      for (let j = 1; j <= names.length; j += 1) {
        if (reach[j - 1] === 1 && segmentMatches(segment, names[j - 1] as string)) next[j] = 1;
      }
    }
    [reach, next] = [next, reach];
  }
  return reach[names.length] === 1;
}

const PROBE_PATHS = [
  "a",
  "a.js",
  ".a",
  "a/b",
  "a/b/c.ts",
  "src/app/main.go",
  "dir/.hidden/file.py",
  "x/y/z/w/v.vue",
];

/** True when the pattern matches every one of a set of unrelated sample paths (e.g. `**`, `*`). */
export function matchesEverything(glob: CompiledGlob): boolean {
  return PROBE_PATHS.every((probe) => globMatches(glob, probe));
}

/**
 * Hard bound on the work of one `PathMatcher` (one scan): table cells filled by all matches.
 * Per-pattern limits (200 characters, 10 `*` per segment, 4,096-character paths) bound a single
 * match but not the total: patterns like `*?a?a...?a*` defeat the star cap and the prefilter, and
 * 200 of them cost about 33 s per 10,000 typical paths in measurements. 500 million cells take
 * about a second on a laptop; ordinary configurations use a small fraction (200 plain
 * patterns on 20,000 files fill about 6 million). Past the budget `matches` answers false: the
 * remaining files are NOT excluded and not demoted, so the failure direction is always "more is
 * scanned" (callers report `exhausted`).
 */
export const MAX_GLOB_WORK = 500_000_000;

export interface PathMatcher {
  readonly patterns: readonly string[];
  matches(filePath: string | null): boolean;
  /** True once the work budget ran out; later matches all answer false. */
  readonly exhausted: boolean;
  /** Work spent so far, so callers can share one budget across several matchers. */
  readonly work: number;
}

/** One matcher for a list of valid patterns; a path matches when any pattern does. */
export function compilePathMatcher(
  patterns: readonly string[],
  maxWork: number = MAX_GLOB_WORK,
): PathMatcher {
  const globs = [...new Set(patterns)].map(compileGlob);
  let used = 0;
  let exhausted = false;
  return {
    patterns,
    get exhausted() {
      return exhausted;
    },
    get work() {
      return used;
    },
    matches: (filePath) => {
      if (filePath === null || exhausted) return false;
      const before = workDone;
      let matched = false;
      for (const glob of globs) {
        if (globMatches(glob, filePath)) {
          matched = true;
          break;
        }
        if (used + (workDone - before) > maxWork) break;
      }
      used += workDone - before;
      if (used > maxWork) {
        exhausted = true;
        return false; // the answer for the file that crossed the budget is also "not matched"
      }
      return matched;
    },
  };
}
