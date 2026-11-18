import type { JavaAdvisory } from "./advisories.js";

/** A Java version in comparable form. `parts` is [feature, interim, update, patch] (zero padded). */
export interface JavaVersion {
  feature: number;
  parts: readonly number[];
  /** The version as printed, without the `+build` part (`1.8.0_511`, `17.0.21`, `25-ea`). */
  display: string;
  /** `-ea` or `-internal` build: a pre-release of the numbered version. */
  isPreRelease: boolean;
}

const MAX_LINES = 40;
const MAX_LINE_LENGTH = 300;
const MAX_NUMBER_DIGITS = 6;
const VERSION_MARKER = ' version "';

function parseNumber(text: string): number | null {
  if (text.length === 0 || text.length > MAX_NUMBER_DIGITS) return null;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 48 || code > 57) return null;
  }
  return Number(text);
}

function parseNumbers(texts: readonly string[]): number[] | null {
  const numbers: number[] = [];
  for (const text of texts) {
    const value = parseNumber(text);
    if (value === null) return null;
    numbers.push(value);
  }
  return numbers;
}

/**
 * One version token: `17.0.21`, `1.8.0_511` (= 8u511), `8u511`, `21.0.13+9`, `25-ea`,
 * `17.0.21-internal`. Anything else returns `null`. Linear: no regular expressions.
 */
export function parseJavaVersionToken(token: string): JavaVersion | null {
  const trimmed = token.trim();
  if (trimmed.length === 0 || trimmed.length > 60) return null;
  let cut = trimmed.length;
  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i];
    if (ch === "+" || ch === "-") {
      cut = i;
      break;
    }
  }
  const core = trimmed.slice(0, cut);
  const suffix = trimmed.slice(cut + 1).toLowerCase();
  const isPreRelease =
    cut < trimmed.length &&
    trimmed[cut] === "-" &&
    (suffix.startsWith("ea") || suffix.startsWith("internal"));
  let parts: number[] | null = null;
  const updateAt = core.indexOf("u");
  if (updateAt > 0) {
    // 8u511
    const numbers = parseNumbers([core.slice(0, updateAt), core.slice(updateAt + 1)]);
    if (numbers !== null) parts = [numbers[0] as number, 0, numbers[1] as number];
  } else if (core.startsWith("1.")) {
    // 1.8.0_511 (the pre-9 scheme): the feature release is the second number
    const [base = "", update] = core.split("_");
    const numbers = parseNumbers(base.split("."));
    const updateNumber = update === undefined ? 0 : parseNumber(update);
    if (numbers !== null && numbers.length === 3 && updateNumber !== null) {
      parts = [numbers[1] as number, numbers[2] as number, updateNumber];
    }
  } else {
    const numbers = parseNumbers(core.split("."));
    if (numbers !== null && numbers.length <= 4) parts = numbers;
  }
  if (parts === null || (parts[0] as number) < 1) return null;
  const padded = [...parts, 0, 0, 0, 0].slice(0, 4);
  return {
    feature: padded[0] as number,
    parts: padded,
    display: isPreRelease ? `${core}-${suffix}` : core,
    isPreRelease,
  };
}

/**
 * The version in `java -version` output: the first `openjdk version "..."` or `java version "..."`
 * line among the first lines. Noise lines before it (`Picked up JAVA_TOOL_OPTIONS`) are skipped;
 * localized or garbage output returns `null`.
 */
export function parseJavaVersionOutput(output: string): JavaVersion | null {
  const lines = output.split("\n", MAX_LINES);
  for (const rawLine of lines) {
    const line = rawLine.slice(0, MAX_LINE_LENGTH);
    const marker = line.indexOf(VERSION_MARKER);
    if (marker <= 0) continue;
    const product = line.slice(0, marker).trim().toLowerCase();
    if (product !== "openjdk" && product !== "java") continue;
    const start = marker + VERSION_MARKER.length;
    const end = line.indexOf('"', start);
    if (end < 0) return null;
    return parseJavaVersionToken(line.slice(start, end));
  }
  return null;
}

export function compareJavaVersions(a: JavaVersion, b: JavaVersion): number {
  for (let i = 0; i < 4; i += 1) {
    const diff = (a.parts[i] ?? 0) - (b.parts[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * The entries that list this version: same feature release and not newer than the highest listed
 * version. Other feature releases are never listed (the vendor notice says nothing about them).
 */
export function matchJavaAdvisories(
  version: JavaVersion,
  table: readonly JavaAdvisory[],
): JavaAdvisory[] {
  return table.filter((entry) =>
    entry.affected.some((release) => {
      if (release.feature !== version.feature) return false;
      const highest = parseJavaVersionToken(release.highest);
      return highest !== null && compareJavaVersions(version, highest) <= 0;
    }),
  );
}

export type JavaVerdict =
  | { kind: "listed"; entries: JavaAdvisory[] }
  /** A release line the notice does not cover that is older than the newest one it does. */
  | { kind: "older-line" }
  | { kind: "not-listed" };

/**
 * Listed, or not. A feature release the notice does not name and that is older than the newest
 * one it names (7, 9, 10, 12, 22 ... for this table) is out of the vendor's support window: it
 * says nothing about it, so it must not read as a neutral "not in the list".
 */
export function judgeJavaVersion(
  version: JavaVersion,
  table: readonly JavaAdvisory[],
): JavaVerdict {
  const entries = matchJavaAdvisories(version, table);
  if (entries.length > 0) return { kind: "listed", entries };
  const isOlderLine = table.some((entry) => {
    const features = entry.affected.map((release) => release.feature);
    return !features.includes(version.feature) && version.feature < Math.max(...features);
  });
  return isOlderLine ? { kind: "older-line" } : { kind: "not-listed" };
}
