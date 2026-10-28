import type { RawSourceFinding } from "../finding-factory.js";

/**
 * Spring Boot configuration files: `application.properties`, `application-*.properties`,
 * `application.yml`, `application-*.yml` (and `.yaml`). Read as text with a small parser of
 * their own (no YAML dependency): block mappings, lists of scalars, flow lists, quoted scalars,
 * comments and `---` documents. Anchors (`&`), aliases (`*`), merge keys (`<<`), nested or
 * multi-line flow collections, tabs for indentation and lines over 4 KiB are not followed: they
 * make the file "malformed" for this reader, which the scan reports as partial
 * (`source:jvm-config`), never as a clean result.
 */
export const MAX_SPRING_CONFIG_BYTES = 256 * 1024;
export const SPRING_CONFIG_NAME = /^application(?:-[\w.-]+)?\.(?:properties|ya?ml)$/i;
const MAX_FINDINGS_PER_FILE = 25;

export interface ConfigEntry {
  key: string;
  value: string;
  line: number;
}

export interface ParsedConfig {
  /** One list per YAML document (a properties file has one). */
  documents: ConfigEntry[][];
  /** The first line the parser could not read, or null. */
  malformedLine: number | null;
}

// ------------------------------------------------------------------------------- properties

/**
 * A line longer than this is not read (it makes the file malformed). Every scan of a line is
 * linear, and the cap keeps even a hostile line cheap.
 */
export const MAX_CONFIG_LINE = 4096;

/** Number of backslashes that end the text. */
function trailingBackslashes(text: string): number {
  let count = 0;
  while (count < text.length && text[text.length - 1 - count] === "\\") count += 1;
  return count;
}

const trimStart = (text: string): string => {
  let index = 0;
  while (
    index < text.length &&
    (text[index] === " " || text[index] === "\t" || text[index] === "\f")
  ) {
    index += 1;
  }
  return text.slice(index);
};

export function parseProperties(text: string): ParsedConfig {
  const entries: ConfigEntry[] = [];
  let malformedLine: number | null = null;
  const lines = text.replace(/^﻿/, "").split(/\r\n|\r|\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const start = index + 1;
    let line = trimStart(lines[index] as string);
    if (line === "" || line.startsWith("#") || line.startsWith("!")) continue;
    // A trailing backslash (an odd number of them) continues the line.
    let tooLong = line.length > MAX_CONFIG_LINE;
    while (!tooLong && trailingBackslashes(line) % 2 === 1 && index + 1 < lines.length) {
      index += 1;
      line = `${line.slice(0, -1)}${trimStart(lines[index] as string)}`;
      tooLong = line.length > MAX_CONFIG_LINE;
    }
    if (tooLong) {
      malformedLine ??= start;
      continue;
    }
    // The key ends at the first unescaped `=`, `:` or white space.
    let split = 0;
    while (split < line.length) {
      const char = line[split] as string;
      if (char === "\\") split += 2;
      else if (char === "=" || char === ":" || char === " " || char === "\t" || char === "\f")
        break;
      else split += 1;
    }
    if (/\\u(?![0-9a-fA-F]{4})/.test(line)) malformedLine ??= start;
    const key = line
      .slice(0, split)
      .replace(/\\(.)/g, "$1")
      .replace(/\[\d+\]/g, "");
    if (key === "") {
      malformedLine ??= start;
      continue;
    }
    let valueStart = split;
    while (valueStart < line.length && /[ \t\f]/.test(line[valueStart] as string)) valueStart += 1;
    if (line[valueStart] === "=" || line[valueStart] === ":") {
      valueStart += 1;
      while (valueStart < line.length && /[ \t\f]/.test(line[valueStart] as string))
        valueStart += 1;
    }
    entries.push({ key, value: line.slice(valueStart).trim(), line: start });
  }
  return { documents: [entries], malformedLine };
}

// ------------------------------------------------------------------------------------- YAML

function stripComment(raw: string): string {
  let quote: string | null = null;
  // The last character that was not white space, for "does a scalar start here".
  let previous = "";
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index] as string;
    if (quote !== null) {
      if (char === "\\" && quote === '"') index += 1;
      else if (char === quote) quote = null;
      previous = char;
      continue;
    }
    if (char === '"' || char === "'") {
      // A quote only opens a string at the start of a scalar.
      if (previous === "" || ":,[{-".includes(previous)) quote = char;
    } else if (char === "#" && (index === 0 || /\s/.test(raw[index - 1] as string))) {
      return raw.slice(0, index).trimEnd();
    }
    if (!/\s/.test(char)) previous = char;
  }
  return raw.trimEnd();
}

function unquote(raw: string): { text: string; ok: boolean } {
  const value = raw.trim();
  if (value.startsWith('"')) {
    const end = value.lastIndexOf('"');
    return end > 0
      ? { text: value.slice(1, end).replace(/\\(.)/g, "$1"), ok: true }
      : { text: value, ok: false };
  }
  if (value.startsWith("'")) {
    const end = value.lastIndexOf("'");
    return end > 0
      ? { text: value.slice(1, end).replace(/''/g, "'"), ok: true }
      : { text: value, ok: false };
  }
  return { text: value, ok: true };
}

/** `[a, "b"]` as a comma-separated string, or null when it is not a one-line flow list. */
function flowList(value: string): string | null {
  if (!value.startsWith("[") || !value.endsWith("]")) return null;
  const inner = value.slice(1, -1);
  const parts: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (const char of inner) {
    if (quote !== null) {
      current += char;
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
      current += char;
    } else if (char === "[" || char === "{") {
      // A nested collection: not followed.
      return null;
    } else if (char === ",") {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (quote !== null) return null;
  parts.push(current);
  const items = parts.map((part) => part.trim());
  // Anchors, aliases and tags in a flow list are not followed.
  if (items.some((item) => /^[&*]/.test(item))) return null;
  return items
    .map((part) => unquote(part).text)
    .filter((part) => part !== "")
    .join(",");
}

/**
 * Splits a block mapping line at its key: a quoted key, or the text before the first `:` that
 * is followed by white space or the end of the line. One pass over the line, no backtracking.
 * Returns null when the line is not `key: value` (or starts with an indicator this reader does
 * not follow: flow collections, anchors, aliases, tags, block scalar and directive marks).
 */
function splitKey(content: string): { key: string; value: string } | null {
  const first = content[0] as string;
  let keyEnd = -1;
  let key: string;
  if (first === '"' || first === "'") {
    let index = 1;
    for (; index < content.length; index += 1) {
      const char = content[index] as string;
      if (first === '"' && char === "\\") index += 1;
      else if (char === first) {
        if (first === "'" && content[index + 1] === "'") index += 1;
        else break;
      }
    }
    if (index >= content.length) return null;
    key = unquote(content.slice(0, index + 1)).text;
    keyEnd = index + 1;
    while (keyEnd < content.length && content[keyEnd] === " ") keyEnd += 1;
    if (content[keyEnd] !== ":") return null;
  } else {
    if ("[]{},&*!|>%@`#'\"".includes(first)) return null;
    if (first === "-" && (content.length === 1 || /\s/.test(content[1] as string))) return null;
    for (let index = 0; index < content.length; index += 1) {
      if (
        content[index] === ":" &&
        (index + 1 === content.length || /\s/.test(content[index + 1] as string))
      ) {
        keyEnd = index;
        break;
      }
    }
    if (keyEnd === -1) return null;
    key = content.slice(0, keyEnd).trimEnd();
    if (key === "") return null;
  }
  const after = content.slice(keyEnd + 1);
  if (after !== "" && !/^\s/.test(after)) return null;
  return { key, value: after.trim() };
}

export function parseYaml(text: string): ParsedConfig {
  const documents: ConfigEntry[][] = [[]];
  let malformedLine: number | null = null;
  const bad = (line: number): void => {
    malformedLine ??= line;
  };
  const lines = text.replace(/^﻿/, "").split(/\r\n|\r|\n/);
  // Open mapping keys, outermost first, with the indent of each.
  let stack: Array<{ indent: number; name: string }> = [];
  /** The key a following list belongs to. */
  let listOwner: { entry: ConfigEntry | null; indent: number } | null = null;
  const pathOf = (key: string): string => [...stack.map((item) => item.name), key].join(".");
  for (let index = 0; index < lines.length; index += 1) {
    const number = index + 1;
    const raw = lines[index] as string;
    if (raw.length > MAX_CONFIG_LINE) {
      bad(number);
      continue;
    }
    let indent = 0;
    while (raw[indent] === " ") indent += 1;
    const rest = raw.slice(indent);
    if (rest.startsWith("\t")) {
      bad(number);
      continue;
    }
    const content = stripComment(rest);
    if (content === "") continue;
    if (content === "---" || content.startsWith("--- ")) {
      documents.push([]);
      stack = [];
      listOwner = null;
      continue;
    }
    if (content === "...") continue;
    if (content.startsWith("%")) continue;
    const document = documents[documents.length - 1] as ConfigEntry[];
    if (content === "-" || content.startsWith("- ")) {
      const item = content === "-" ? "" : content.slice(2).trim();
      if (/^[&*!{]/.test(item)) bad(number);
      else if (listOwner !== null && listOwner.entry !== null && indent >= listOwner.indent) {
        // A map inside a list (`- name: x`) is not a scalar list: nothing to read from it.
        if (/^["']/.test(item) || splitKey(item) === null) {
          const scalar = unquote(item);
          if (!scalar.ok) bad(number);
          listOwner.entry.value =
            listOwner.entry.value === "" ? scalar.text : `${listOwner.entry.value},${scalar.text}`;
        }
      }
      continue;
    }
    const split = splitKey(content);
    if (split === null) {
      bad(number);
      continue;
    }
    while (stack.length > 0 && (stack[stack.length - 1] as { indent: number }).indent >= indent) {
      stack.pop();
    }
    const key = split.key;
    // A merge key pulls in a whole mapping: not followed.
    if (key === "<<") bad(number);
    const rawValue = split.value;
    if (rawValue === "") {
      // A container; a list under it (at the same indent or deeper) fills its value.
      const entry: ConfigEntry = { key: pathOf(key), value: "", line: number };
      document.push(entry);
      stack.push({ indent, name: key });
      listOwner = { entry, indent };
      continue;
    }
    listOwner = null;
    if (rawValue.startsWith("&") || rawValue.startsWith("*")) {
      // An anchor or an alias: not followed.
      bad(number);
      continue;
    }
    if (rawValue.startsWith("|") || rawValue.startsWith(">")) {
      // A block scalar: skip its lines.
      document.push({ key: pathOf(key), value: "", line: number });
      while (index + 1 < lines.length) {
        const next = lines[index + 1] as string;
        let nextIndent = 0;
        while (next[nextIndent] === " ") nextIndent += 1;
        if (next.trim() === "" || nextIndent > indent) index += 1;
        else break;
      }
      continue;
    }
    if (rawValue.startsWith("{")) {
      // A one-line flow map of scalars: `{a: b, c: d}`; nesting and longer maps are not followed.
      const inner = rawValue.slice(1, -1);
      if (!rawValue.endsWith("}") || /[{}[\]]/.test(inner)) {
        bad(number);
        continue;
      }
      for (const part of inner.split(",")) {
        const colon = part.indexOf(":");
        if (colon === -1) {
          if (part.trim() !== "") bad(number);
          continue;
        }
        if (/^\s*[&*]/.test(part.slice(colon + 1))) {
          bad(number);
          continue;
        }
        document.push({
          key: pathOf(`${key}.${unquote(part.slice(0, colon)).text}`),
          value: unquote(part.slice(colon + 1)).text,
          line: number,
        });
      }
      continue;
    }
    if (rawValue.startsWith("[")) {
      const list = flowList(rawValue);
      if (list === null) {
        bad(number);
        continue;
      }
      document.push({ key: pathOf(key), value: list, line: number });
      continue;
    }
    const scalar = unquote(rawValue);
    if (!scalar.ok) {
      bad(number);
      continue;
    }
    document.push({ key: pathOf(key), value: scalar.text, line: number });
  }
  return { documents, malformedLine };
}

// ---------------------------------------------------------------------------- the rules

export interface SpringConfigAnalysis {
  findings: RawSourceFinding[];
  /** A line the parser could not read (the file was read only in part), or null. */
  malformedLine: number | null;
  capped: boolean;
  /** `management.endpoints.web.exposure.include` exposes everything: a finding once the project is known to have no security. */
  actuatorExposure: Array<{ path: string; line: number; lowered: boolean }>;
}

const normalize = (key: string): string => key.toLowerCase().replace(/[-_]/g, "");
const DEV_PROFILE =
  /^(?:dev|development|local|test|testing|debug|docker|h2|demo|ci|e2e|it|sandbox)$/i;

/** Profiles a file or YAML document is limited to (`application-dev.yml`, `on-profile: dev`). */
function profileSaysDevelopment(profiles: string[]): boolean {
  const names = profiles
    .flatMap((profile) => profile.split(/[,\s|&()!]+/))
    .filter((name) => name !== "");
  return names.length > 0 && names.every((name) => DEV_PROFILE.test(name));
}

type Flag = "false" | "true" | "default-false" | "other";

const FALSE_WORDS = new Set(["false", "off", "no", "n", "0"]);
const TRUE_WORDS = new Set(["true", "on", "yes", "y", "1"]);

/**
 * `false`, `off`, `no` and `0` (quoted or not, any case) are false; `true`, `on`, `yes` and `1`
 * are the only safe values. Everything else (a `${VAR}` placeholder, `@token@`, `!!bool false`)
 * cannot be read as a fixed value: it is `other`, and `${VAR:false}` is `default-false`.
 */
function flagOf(value: string): Flag {
  let text = value.trim().toLowerCase();
  if (
    text.length >= 2 &&
    (text[0] === '"' || text[0] === "'") &&
    text.endsWith(text[0] as string)
  ) {
    text = text.slice(1, -1).trim();
  }
  if (FALSE_WORDS.has(text)) return "false";
  if (TRUE_WORDS.has(text)) return "true";
  // `${COOKIE_SECURE:false}`: an environment variable with a default of false.
  // `[^}:]+` and `[^}]*` cannot overlap with the `:` between them: one linear pass.
  const placeholder = /^\$\{[^}:]+:([^}]*)\}$/.exec(text);
  if (placeholder !== null && FALSE_WORDS.has((placeholder[1] as string).trim())) {
    return "default-false";
  }
  return "other";
}

export function analyzeSpringConfig(
  text: string,
  path: string,
  kind: "properties" | "yaml",
): SpringConfigAnalysis {
  const parsed = kind === "yaml" ? parseYaml(text) : parseProperties(text);
  const fileProfile = /^application-(.+)\.[^.]+$/i.exec(path.slice(path.lastIndexOf("/") + 1))?.[1];
  const findings: RawSourceFinding[] = [];
  const actuatorExposure: SpringConfigAnalysis["actuatorExposure"] = [];
  let capped = false;
  const push = (finding: RawSourceFinding): void => {
    if (findings.length >= MAX_FINDINGS_PER_FILE) capped = true;
    else findings.push(finding);
  };
  for (const entries of parsed.documents) {
    const profile = entries.find(
      (entry) =>
        entry.key === "spring.config.activate.on-profile" || entry.key === "spring.profiles",
    )?.value;
    // A document that names its own profile overrides the one in the file name.
    const profiles = [profile ?? fileProfile].filter(
      (name): name is string => name !== undefined && name !== "",
    );
    const development = profileSaysDevelopment(profiles);
    const profileNote = profiles.length > 0 ? ` (profile ${profiles.join(", ")})` : "";
    for (const entry of entries) {
      const key = normalize(entry.key);
      const cookie = /^server\.(?:(?:servlet|reactive)\.)?session\.cookie\.(httponly|secure)$/.exec(
        key,
      );
      const flag = flagOf(entry.value);
      if (cookie !== null && flag !== "true") {
        const name = cookie[1] === "httponly" ? "HttpOnly" : "Secure";
        const inferred = flag !== "false" || development;
        push({
          ruleId: "PG-COOKIE-001",
          path,
          line: entry.line,
          severity: "medium",
          status: "suspected",
          confidence: inferred ? "low" : "medium",
          evidence: `${entry.key}=${entry.value} ${
            flag === "other"
              ? `is not a fixed true, so the session cookie may be sent without ${name}`
              : `sends the session cookie without ${name}`
          }${profileNote}${
            flag === "default-false"
              ? "; the value is an environment variable that defaults to false"
              : ""
          }${inferred ? "; inferred" : ""}`,
          cause: `prop:session-cookie-${name.toLowerCase()}`,
        });
        continue;
      }
      if (key === "spring.security.debug" && entry.value.trim().toLowerCase() === "true") {
        push(debugFinding(path, entry, `${entry.key}=true`, development, profileNote));
        continue;
      }
      if (
        key.startsWith("logging.level.org.springframework.security") &&
        /^(?:debug|trace)$/i.test(entry.value.trim())
      ) {
        push(debugFinding(path, entry, `${entry.key}=${entry.value}`, development, profileNote));
        continue;
      }
      if (key === "management.endpoints.web.exposure.include") {
        const names = entry.value.split(/[,\s]+/).map((name) => name.trim());
        if (names.includes("*")) {
          actuatorExposure.push({ path, line: entry.line, lowered: development });
        }
      }
    }
  }
  return { findings, malformedLine: parsed.malformedLine, capped, actuatorExposure };
}

function debugFinding(
  path: string,
  entry: ConfigEntry,
  setting: string,
  development: boolean,
  profileNote: string,
): RawSourceFinding {
  return {
    ruleId: "PG-CONF-001",
    path,
    line: entry.line,
    severity: "low",
    status: "suspected",
    confidence: development ? "low" : "medium",
    evidence: `${setting} writes request details and security filter decisions to the log${profileNote}${
      development ? "; development profile; inferred" : ""
    }`,
    cause: "prop:security-debug",
  };
}

/** The finding for `exposure.include=*` in a project that shows no Spring Security. */
export function actuatorFinding(
  exposure: { path: string; line: number },
  reason: string,
): RawSourceFinding {
  return {
    ruleId: "PG-CONF-001",
    path: exposure.path,
    line: exposure.line,
    severity: "low",
    status: "suspected",
    confidence: "low",
    evidence: `management.endpoints.web.exposure.include=* exposes every Actuator endpoint (env, heapdump, beans, ...) and ${reason}; inferred`,
    cause: "prop:actuator-exposure",
  };
}
