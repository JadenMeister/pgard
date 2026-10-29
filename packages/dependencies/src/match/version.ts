import type { Ecosystem } from "../types.js";

/**
 * Version semantics per OSV ecosystem. A scheme answers one question: how do two version strings
 * of this ecosystem order? When a string is not a valid version of the scheme it returns `null`,
 * and the caller reports "not tested" for that package instead of guessing.
 *
 * Supported: `npm` (semver 2.0.0, as OSV `SEMVER` ranges) and `Go` (module versions are semver
 * with a leading `v`; OSV records them without it). Maven, PyPI (PEP 440) and Packagist have no
 * scheme here because PGARD neither parses their lockfiles nor downloads their OSV data yet; a
 * package of another ecosystem therefore has no scheme and is never matched.
 */
export interface VersionScheme {
  /** Parsed form of a version, or `null` when it is not valid in this scheme. */
  parse(version: string): ParsedVersion | null;
  compare(a: ParsedVersion, b: ParsedVersion): number;
  /** Human-readable form of a version as OSV states it (no leading `v`, no build metadata). */
  display(version: ParsedVersion): string;
}

export interface ParsedVersion {
  major: bigint;
  minor: bigint;
  patch: bigint;
  /** Dot-separated pre-release identifiers; empty for a release. */
  pre: (bigint | string)[];
  text: string;
}

const NUMERIC = /^(0|[1-9]\d*)$/;
const IDENT = /^[0-9A-Za-z-]+$/;
const MAX_VERSION_LENGTH = 256;

function parseSemver(raw: string, allowV: boolean): ParsedVersion | null {
  if (raw.length === 0 || raw.length > MAX_VERSION_LENGTH) return null;
  let text = raw;
  if (allowV && text.startsWith("v")) text = text.slice(1);
  const plus = text.indexOf("+");
  if (plus !== -1) {
    const build = text.slice(plus + 1);
    // Go: `+incompatible` marks a v2+ module without a go.mod; it does not affect ordering.
    if (build === "") return null;
    if (!build.split(".").every((part) => IDENT.test(part))) return null;
    text = text.slice(0, plus);
  }
  const dash = text.indexOf("-");
  const core = dash === -1 ? text : text.slice(0, dash);
  const preText = dash === -1 ? null : text.slice(dash + 1);
  const numbers = core.split(".");
  if (numbers.length !== 3 || !numbers.every((part) => NUMERIC.test(part))) return null;
  const pre: (bigint | string)[] = [];
  if (preText !== null) {
    if (preText === "") return null;
    for (const part of preText.split(".")) {
      if (!IDENT.test(part)) return null;
      if (/^\d+$/.test(part)) {
        if (!NUMERIC.test(part)) return null; // leading zeros are not allowed in numeric ids
        pre.push(BigInt(part));
      } else {
        pre.push(part);
      }
    }
  }
  return {
    major: BigInt(numbers[0] as string),
    minor: BigInt(numbers[1] as string),
    patch: BigInt(numbers[2] as string),
    pre,
    text,
  };
}

function compareSemver(a: ParsedVersion, b: ParsedVersion): number {
  for (const key of ["major", "minor", "patch"] as const) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  if (a.pre.length === 0 || b.pre.length === 0) {
    if (a.pre.length === b.pre.length) return 0;
    return a.pre.length === 0 ? 1 : -1; // a release is newer than its pre-releases
  }
  const length = Math.min(a.pre.length, b.pre.length);
  for (let index = 0; index < length; index += 1) {
    const left = a.pre[index] as bigint | string;
    const right = b.pre[index] as bigint | string;
    if (left === right) continue;
    const leftNumber = typeof left === "bigint";
    const rightNumber = typeof right === "bigint";
    if (leftNumber && rightNumber) return left < right ? -1 : 1;
    if (leftNumber) return -1; // numeric identifiers sort before alphanumeric ones
    if (rightNumber) return 1;
    return left < right ? -1 : 1;
  }
  return a.pre.length === b.pre.length ? 0 : a.pre.length < b.pre.length ? -1 : 1;
}

const displaySemver = (version: ParsedVersion): string => version.text;

const NPM_SCHEME: VersionScheme = {
  parse: (version) => parseSemver(version, false),
  compare: compareSemver,
  display: displaySemver,
};

const GO_SCHEME: VersionScheme = {
  parse: (version) => parseSemver(version, true),
  compare: compareSemver,
  display: displaySemver,
};

/** The scheme of an ecosystem, or `null` when PGARD has none (then nothing is matched). */
export function versionScheme(ecosystem: Ecosystem | string): VersionScheme | null {
  if (ecosystem === "npm") return NPM_SCHEME;
  if (ecosystem === "Go") return GO_SCHEME;
  return null;
}
