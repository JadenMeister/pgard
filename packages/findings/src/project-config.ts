import { INVISIBLE_CHARACTERS, globProblem } from "./glob.js";

/**
 * Project configuration file: `pgard.config.json` at the Git root. It is part of the scanned
 * repository, so it is untrusted input: data only, never executed, strictly validated.
 *
 * ```json
 * {
 *   "version": 1,
 *   "exclude": ["legacy/**", "*.generated.ts"],
 *   "testDirectories": ["e2e", "tools/samples"],
 *   "suppressions": [
 *     { "ruleId": "PG-SQL-001", "path": "scripts/**", "reason": "Admin-only script", "expires": "2027-01-31" }
 *   ]
 * }
 * ```
 *
 * `precommit` (`{ "mode": "block" | "warn", "whenNotScanned": "block" | "warn" }`) only sets what
 * the `pgard precommit` hook does with a result.
 *
 * Deliberately not configurable: authorization, hosts, ports, network targets and rule
 * severities. Any key not listed here is rejected, so a config can never widen what PGARD
 * contacts or relax the authorization gate.
 */

export const PROJECT_CONFIG_FILE = "pgard.config.json";
export const PROJECT_CONFIG_VERSION = 1;
export const MAX_PROJECT_CONFIG_BYTES = 64 * 1024;
export const MAX_EXCLUDE_PATTERNS = 200;
export const MAX_TEST_DIRECTORIES = 100;
export const MAX_SUPPRESSIONS = 200;
export const MAX_SUPPRESSION_REASON_LENGTH = 300;
const MAX_JSON_DEPTH = 8;
const MAX_REPORTED_PROBLEMS = 10;
const RULE_ID = /^PG-[A-Z0-9]{2,12}-\d{3}$/;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

export interface ProjectSuppression {
  ruleId: string;
  /** Glob (same syntax as `exclude`). */
  path: string;
  reason: string;
  /** `YYYY-MM-DD`, when set. */
  expires?: string;
}

/**
 * `pgard precommit` settings. Both values only decide what the commit hook does with a result;
 * neither can skip or relax the authorization checks.
 */
export interface PrecommitConfig {
  /** `block` exits non-zero on a finding and stops the commit; `warn` prints and exits 0. */
  mode?: "block" | "warn";
  /**
   * What happens when nothing (or not everything) could be scanned: not authorized, an error, a
   * timeout, a file over the size limit. Unset: the same as `mode`, so a `block` hook blocks.
   */
  whenNotScanned?: "block" | "warn";
}

export const PRECOMMIT_MODES: readonly ("block" | "warn")[] = ["block", "warn"];

export interface ProjectConfig {
  version: 1;
  exclude: string[];
  testDirectories: string[];
  /** Parsed and validated only; applying them is a later step. */
  suppressions: ProjectSuppression[];
  /** Only for `pgard precommit`; absent means the defaults (`block`). */
  precommit?: PrecommitConfig;
}

export type ProjectConfigParse =
  { ok: true; config: ProjectConfig } | { ok: false; problems: string[] };

type JsonValue = null | boolean | number | string | JsonValue[] | Map<string, JsonValue>;

class ConfigSyntaxError extends Error {}

/**
 * Strict JSON reader (RFC 8259): no comments, no trailing commas, no duplicate object keys, a
 * depth limit. Objects become `Map`s, so keys such as `__proto__` are plain data.
 */
function parseStrictJson(text: string): JsonValue {
  let index = 0;
  const fail = (message: string): never => {
    throw new ConfigSyntaxError(`${message} at character ${index}`);
  };
  const skipSpace = () => {
    while (index < text.length && " \t\n\r".includes(text.charAt(index))) index += 1;
  };
  const parseString = (): string => {
    index += 1; // opening quote
    let result = "";
    for (;;) {
      if (index >= text.length) return fail("unterminated string");
      const char = text.charAt(index);
      if (char === '"') {
        index += 1;
        if (INVISIBLE_CHARACTERS.test(result)) {
          return fail("string with a bidirectional, zero-width or other format character");
        }
        return result;
      }
      if (char.charCodeAt(0) < 0x20) return fail("control character in string");
      if (char !== "\\") {
        result += char;
        index += 1;
        continue;
      }
      const escape = text.charAt(index + 1);
      index += 2;
      const simple: Record<string, string> = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      if (escape in simple) {
        result += simple[escape];
      } else if (escape === "u") {
        const hex = text.slice(index, index + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) return fail("invalid \\u escape");
        result += String.fromCharCode(Number.parseInt(hex, 16));
        index += 4;
      } else {
        return fail("invalid escape");
      }
    }
  };
  const parseValue = (depth: number): JsonValue => {
    if (depth > MAX_JSON_DEPTH) return fail("nesting too deep");
    skipSpace();
    const char = text.charAt(index);
    if (char === "{") {
      index += 1;
      const object = new Map<string, JsonValue>();
      skipSpace();
      if (text.charAt(index) === "}") {
        index += 1;
        return object;
      }
      for (;;) {
        skipSpace();
        if (text.charAt(index) !== '"') return fail("expected a string key");
        const key = parseString();
        if (object.has(key))
          throw new ConfigSyntaxError(`duplicate key ${JSON.stringify(key.slice(0, 40))}`);
        skipSpace();
        if (text.charAt(index) !== ":") return fail("expected ':'");
        index += 1;
        object.set(key, parseValue(depth + 1));
        skipSpace();
        const next = text.charAt(index);
        index += 1;
        if (next === "}") return object;
        if (next !== ",") {
          index -= 1;
          return fail("expected ',' or '}'");
        }
      }
    }
    if (char === "[") {
      index += 1;
      const array: JsonValue[] = [];
      skipSpace();
      if (text.charAt(index) === "]") {
        index += 1;
        return array;
      }
      for (;;) {
        array.push(parseValue(depth + 1));
        skipSpace();
        const next = text.charAt(index);
        index += 1;
        if (next === "]") return array;
        if (next !== ",") {
          index -= 1;
          return fail("expected ',' or ']'");
        }
      }
    }
    if (char === '"') return parseString();
    const literal = /^(?:true|false|null)/.exec(text.slice(index, index + 5));
    if (literal) {
      index += literal[0].length;
      return literal[0] === "null" ? null : literal[0] === "true";
    }
    const number = /^-?(?:0|[1-9]\d{0,15})(?:\.\d{1,16})?(?:[eE][+-]?\d{1,4})?/.exec(
      text.slice(index, index + 40),
    );
    if (number) {
      index += number[0].length;
      return Number(number[0]);
    }
    return fail("unexpected character");
  };
  const value = parseValue(0);
  skipSpace();
  if (index < text.length) fail("unexpected text after the JSON value");
  return value;
}

function show(text: string): string {
  const clipped = text.length > 40 ? `${text.slice(0, 40)}...` : text;
  return JSON.stringify(clipped);
}

function isRealDate(value: string): boolean {
  const match = DATE.exec(value);
  if (!match) return false;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
  );
}

function checkKeys(
  object: Map<string, JsonValue>,
  where: string,
  required: readonly string[],
  optional: readonly string[],
  problems: string[],
): void {
  for (const key of object.keys()) {
    if (!required.includes(key) && !optional.includes(key)) {
      problems.push(`${where}: unknown key ${show(key)} (not configurable)`);
    }
  }
  for (const key of required) {
    if (!object.has(key)) problems.push(`${where}: missing required key "${key}"`);
  }
}

function checkGlobList(
  value: JsonValue | undefined,
  name: string,
  max: number,
  problems: string[],
): string[] {
  if (!Array.isArray(value)) {
    problems.push(`${name}: must be an array of path patterns`);
    return [];
  }
  if (value.length > max) {
    problems.push(`${name}: at most ${max} entries are allowed (found ${value.length})`);
    return [];
  }
  const result: string[] = [];
  value.forEach((entry, position) => {
    const problem = globProblem(entry);
    if (problem !== null) problems.push(`${name}[${position}]: ${problem}`);
    else result.push(entry as string);
  });
  return result;
}

/**
 * Parses and validates the text of a project configuration file. Never throws. Reports every
 * problem found (up to 10) and returns no partial config: either the whole file is accepted or
 * it is invalid.
 */
export function parseProjectConfig(text: string): ProjectConfigParse {
  const source = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  if (new TextEncoder().encode(source).length > MAX_PROJECT_CONFIG_BYTES) {
    return { ok: false, problems: [`the file is larger than ${MAX_PROJECT_CONFIG_BYTES} bytes`] };
  }
  let root: JsonValue;
  try {
    root = parseStrictJson(source);
  } catch (error) {
    const message = error instanceof ConfigSyntaxError ? error.message : "could not be parsed";
    return { ok: false, problems: [`invalid JSON: ${message}`] };
  }
  if (!(root instanceof Map)) {
    return { ok: false, problems: ["the top level must be a JSON object"] };
  }
  const problems: string[] = [];
  checkKeys(
    root,
    "config",
    ["version"],
    ["exclude", "testDirectories", "suppressions", "precommit"],
    problems,
  );
  if (root.has("version") && root.get("version") !== PROJECT_CONFIG_VERSION) {
    problems.push(`version: must be the number ${PROJECT_CONFIG_VERSION}`);
  }
  const exclude = root.has("exclude")
    ? checkGlobList(root.get("exclude"), "exclude", MAX_EXCLUDE_PATTERNS, problems)
    : [];
  const testDirectories = root.has("testDirectories")
    ? checkGlobList(root.get("testDirectories"), "testDirectories", MAX_TEST_DIRECTORIES, problems)
    : [];
  const suppressions: ProjectSuppression[] = [];
  if (root.has("suppressions")) {
    const list = root.get("suppressions");
    if (!Array.isArray(list)) {
      problems.push("suppressions: must be an array");
    } else if (list.length > MAX_SUPPRESSIONS) {
      problems.push(
        `suppressions: at most ${MAX_SUPPRESSIONS} entries are allowed (found ${list.length})`,
      );
    } else {
      list.forEach((entry, position) => {
        const where = `suppressions[${position}]`;
        if (!(entry instanceof Map)) {
          problems.push(`${where}: must be an object`);
          return;
        }
        checkKeys(entry, where, ["ruleId", "path", "reason"], ["expires"], problems);
        const ruleId = entry.get("ruleId");
        const reason = entry.get("reason");
        const expires = entry.get("expires");
        const before = problems.length;
        if (entry.has("ruleId") && !(typeof ruleId === "string" && RULE_ID.test(ruleId))) {
          problems.push(`${where}.ruleId: must look like PG-SQL-001`);
        }
        const pathProblem = entry.has("path") ? globProblem(entry.get("path")) : null;
        if (pathProblem !== null) problems.push(`${where}.path: ${pathProblem}`);
        if (entry.has("reason")) {
          if (typeof reason !== "string" || reason.trim().length === 0) {
            problems.push(`${where}.reason: a non-empty reason is required`);
          } else if (reason.length > MAX_SUPPRESSION_REASON_LENGTH) {
            problems.push(
              `${where}.reason: must be at most ${MAX_SUPPRESSION_REASON_LENGTH} characters`,
            );
          } else if (CONTROL.test(reason)) {
            problems.push(`${where}.reason: must not contain control characters`);
          }
        }
        if (entry.has("expires") && !(typeof expires === "string" && isRealDate(expires))) {
          problems.push(`${where}.expires: must be a real date written YYYY-MM-DD`);
        }
        if (problems.length === before) {
          suppressions.push({
            ruleId: ruleId as string,
            path: entry.get("path") as string,
            reason: reason as string,
            ...(typeof expires === "string" ? { expires } : {}),
          });
        }
      });
    }
  }
  let precommit: PrecommitConfig | undefined;
  if (root.has("precommit")) {
    const section = root.get("precommit");
    if (!(section instanceof Map)) {
      problems.push("precommit: must be an object");
    } else {
      checkKeys(section, "precommit", [], ["mode", "whenNotScanned"], problems);
      const parsed: PrecommitConfig = {};
      for (const key of ["mode", "whenNotScanned"] as const) {
        if (!section.has(key)) continue;
        const value = section.get(key);
        if (value === "block" || value === "warn") parsed[key] = value;
        else problems.push(`precommit.${key}: must be "block" or "warn"`);
      }
      precommit = parsed;
    }
  }
  if (problems.length > 0) {
    const shown = problems.slice(0, MAX_REPORTED_PROBLEMS);
    const rest = problems.length - shown.length;
    return { ok: false, problems: rest > 0 ? [...shown, `and ${rest} more problem(s)`] : shown };
  }
  return {
    ok: true,
    config: {
      version: 1,
      exclude,
      testDirectories,
      suppressions,
      ...(precommit === undefined ? {} : { precommit }),
    },
  };
}
