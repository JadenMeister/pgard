import type { RawSourceFinding } from "../finding-factory.js";

/**
 * Spring Boot configuration files: `application.properties`, `application-*.properties`,
 * `application.yml`, `application-*.yml` (and `.yaml`). Read as text with a small parser of
 * their own (no YAML dependency): block mappings, lists of scalars, flow lists, quoted scalars,
 * comments and `---` documents. Anchors, multi-line flow collections and tabs for indentation
 * are not followed; they make the file "malformed" for this reader, which the scan reports as
 * partial, never as a clean result.
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

export function parseProperties(text: string): ParsedConfig {
  const entries: ConfigEntry[] = [];
  let malformedLine: number | null = null;
  const lines = text.split(/\r\n|\r|\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const start = index + 1;
    let line = (lines[index] as string).replace(/^[ \t\f]+/, "");
    if (line === "" || line.startsWith("#") || line.startsWith("!")) continue;
    // A trailing backslash (an odd number of them) continues the line.
    while (/(?:^|[^\\])(?:\\\\)*\\$/.test(line) && index + 1 < lines.length) {
      index += 1;
      line = `${line.slice(0, -1)}${(lines[index] as string).replace(/^[ \t\f]+/, "")}`;
    }
    const match = /^((?:[^\s=:\\]|\\.)*)[ \t\f]*(?:[=:][ \t\f]*|[ \t\f]+)?(.*)$/s.exec(line);
    if (match === null) continue;
    if (/\\u(?![0-9a-fA-F]{4})/.test(line)) malformedLine ??= start;
    const key = (match[1] as string).replace(/\\(.)/g, "$1").replace(/\[\d+\]/g, "");
    if (key === "") {
      malformedLine ??= start;
      continue;
    }
    entries.push({ key, value: (match[2] as string).trim(), line: start });
  }
  return { documents: [entries], malformedLine };
}

// ------------------------------------------------------------------------------------- YAML

function stripComment(raw: string): string {
  let quote: string | null = null;
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index] as string;
    if (quote !== null) {
      if (char === "\\" && quote === '"') index += 1;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      // A quote only opens a string at the start of a scalar.
      const before = raw.slice(0, index).trimEnd();
      if (before === "" || /[:,[{-]$/.test(before)) quote = char;
    } else if (char === "#" && (index === 0 || /\s/.test(raw[index - 1] as string))) {
      return raw.slice(0, index).trimEnd();
    }
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
    } else if (char === ",") {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (quote !== null) return null;
  parts.push(current);
  return parts
    .map((part) => unquote(part).text)
    .filter((part) => part !== "")
    .join(",");
}

const KEY_LINE =
  /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s:#'"[\]{},&*!|>%@`-][^:#]*?|-[^\s:][^:#]*?)\s*:(?:\s+(.*))?$/;

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
    const indentMatch = /^( *)(.*)$/.exec(raw) as RegExpExecArray;
    const indent = (indentMatch[1] as string).length;
    const rest = indentMatch[2] as string;
    if (rest.startsWith("\t") || (indentMatch[1] as string).includes("\t")) {
      bad(number);
      continue;
    }
    const content = stripComment(rest);
    if (content === "") continue;
    if (/^---(?:\s|$)/.test(content)) {
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
      if (listOwner !== null && listOwner.entry !== null && indent >= listOwner.indent) {
        // A map inside a list (`- name: x`) is not a scalar list: nothing to read from it.
        if (!KEY_LINE.test(item) || /^["']/.test(item)) {
          const scalar = unquote(item);
          if (!scalar.ok) bad(number);
          listOwner.entry.value =
            listOwner.entry.value === "" ? scalar.text : `${listOwner.entry.value},${scalar.text}`;
        }
      }
      continue;
    }
    const match = KEY_LINE.exec(content);
    if (match === null) {
      bad(number);
      continue;
    }
    while (stack.length > 0 && (stack[stack.length - 1] as { indent: number }).indent >= indent) {
      stack.pop();
    }
    const key = unquote(match[1] as string).text;
    const rawValue = (match[2] ?? "").trim();
    if (rawValue === "" || rawValue.startsWith("&")) {
      // A container; a list under it (at the same indent or deeper) fills its value.
      const entry: ConfigEntry = { key: pathOf(key), value: "", line: number };
      document.push(entry);
      stack.push({ indent, name: key });
      listOwner = { entry, indent };
      continue;
    }
    listOwner = null;
    if (rawValue.startsWith("|") || rawValue.startsWith(">")) {
      // A block scalar: skip its lines.
      document.push({ key: pathOf(key), value: "", line: number });
      while (index + 1 < lines.length) {
        const next = lines[index + 1] as string;
        if (next.trim() === "" || /^ */.exec(next)![0].length > indent) index += 1;
        else break;
      }
      continue;
    }
    if (rawValue.startsWith("{")) {
      // A one-line flow map of scalars: `{a: b, c: d}`; anything longer is not followed.
      if (!rawValue.endsWith("}")) {
        bad(number);
        continue;
      }
      for (const part of rawValue.slice(1, -1).split(",")) {
        const pair = /^\s*([^:]+?)\s*:\s*(.*?)\s*$/.exec(part);
        if (pair === null) {
          if (part.trim() !== "") bad(number);
          continue;
        }
        document.push({
          key: pathOf(`${key}.${unquote(pair[1] as string).text}`),
          value: unquote(pair[2] as string).text,
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

type Flag = "false" | "default-false" | "other";

function flagOf(value: string): Flag {
  const text = value.trim().toLowerCase();
  if (text === "false") return "false";
  // `${COOKIE_SECURE:false}`: an environment variable with a default of false.
  if (/^\$\{[^}:]+:\s*false\s*\}$/.test(text)) return "default-false";
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
      if (cookie !== null && flag !== "other") {
        const name = cookie[1] === "httponly" ? "HttpOnly" : "Secure";
        const inferred = flag === "default-false" || development;
        push({
          ruleId: "PG-COOKIE-001",
          path,
          line: entry.line,
          severity: "medium",
          status: "suspected",
          confidence: inferred ? "low" : "medium",
          evidence: `${entry.key}=${entry.value} sends the session cookie without ${name}${profileNote}${
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
