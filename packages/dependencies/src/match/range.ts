import type { ReducedAdvisory } from "../osv/reduce.js";
import type { ParsedVersion, VersionScheme } from "./version.js";

type Affected = ReducedAdvisory["affected"][number];

export type RangeVerdict =
  | {
      verdict: "affected";
      /** E.g. `>=1.0.0 <1.2.3`; how the matching range reads. */
      range: string;
      /** `fixed` versions of the matching entry that are newer than the installed one. */
      fixed: string[];
      via: "range" | "version-list";
    }
  | { verdict: "not-affected" }
  /** The record cannot be compared with this version; the package is "not tested". */
  | { verdict: "unknown"; reason: string };

interface Event {
  kind: "introduced" | "fixed" | "last_affected" | "limit";
  version: string;
  parsed: ParsedVersion | null;
}

const KINDS = ["introduced", "fixed", "last_affected", "limit"] as const;

function eventsOf(raw: Record<string, string>[], scheme: VersionScheme): Event[] | null {
  const events: Event[] = [];
  for (const entry of raw) {
    for (const kind of KINDS) {
      const version = entry[kind];
      if (typeof version !== "string") continue;
      // `introduced: "0"` means "from the very first version".
      const parsed = version === "0" ? null : scheme.parse(version);
      if (version !== "0" && parsed === null) return null; // a boundary we cannot read
      events.push({ kind, version, parsed });
    }
  }
  return events;
}

/**
 * `introduced: "0"` (event `parsed === null`) is below EVERY version, including pre-releases and
 * pseudo-versions such as `v0.0.0-2020...-hash`, which sort below the release `0.0.0`.
 */
function compareToEvent(
  scheme: VersionScheme,
  left: ParsedVersion | null,
  right: ParsedVersion | null,
): number {
  if (left === null) return right === null ? 0 : -1;
  if (right === null) return 1;
  return scheme.compare(left, right);
}

/**
 * OSV range evaluation (https://ossf.github.io/osv-schema/#affectedranges-field): events are
 * ordered by version; `introduced` turns "affected" on at or above its version, `fixed` and
 * `limit` turn it off at or above theirs, `last_affected` turns it off above its version.
 */
function evaluateEvents(
  events: Event[],
  version: ParsedVersion,
  scheme: VersionScheme,
): { affected: boolean; range: string } {
  const sorted = events
    .map((event, index) => ({ event, index }))
    .sort((a, b) => compareToEvent(scheme, a.event.parsed, b.event.parsed) || a.index - b.index)
    .map((item) => item.event);
  let affected = false;
  let lower = "";
  let range = "";
  let isBounded = false;
  for (const event of sorted) {
    const order = compareToEvent(scheme, version, event.parsed);
    if (event.kind === "introduced") {
      if (order >= 0 && !affected) {
        affected = true;
        isBounded = false;
        lower = event.version === "0" ? "" : `>=${event.version}`;
        range = lower;
      }
    } else if (event.kind === "last_affected") {
      if (order > 0) affected = false;
      else if (affected && !isBounded) {
        range = `${lower} <=${event.version}`.trim();
        isBounded = true;
      }
    } else {
      if (order >= 0) affected = false;
      else if (affected && !isBounded) {
        range = `${lower} <${event.version}`.trim();
        isBounded = true;
      }
    }
    if (order < 0 && affected) break;
  }
  return { affected, range: range === "" ? "all versions" : range };
}

/**
 * Whether `installed` is inside the advisory's affected versions of one package entry: listed in
 * `versions`, or inside a `SEMVER` / `ECOSYSTEM` range. `GIT` ranges name commits, not versions,
 * and are ignored. A range with a boundary the scheme cannot read gives `unknown`, unless the
 * exact version list already says "affected".
 */
export function evaluateAffected(
  entry: Affected,
  installed: ParsedVersion,
  scheme: VersionScheme,
): RangeVerdict {
  for (const listed of entry.versions ?? []) {
    const parsed = scheme.parse(listed);
    if (parsed !== null && scheme.compare(parsed, installed) === 0) {
      return {
        verdict: "affected",
        range: `= ${scheme.display(installed)}`,
        fixed: [],
        via: "version-list",
      };
    }
  }
  let unknownReason: string | null = null;
  for (const range of entry.ranges ?? []) {
    if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
    const events = eventsOf(range.events, scheme);
    if (events === null) {
      unknownReason = "an advisory range has a version this ecosystem's scheme cannot read";
      continue;
    }
    const result = evaluateEvents(events, installed, scheme);
    if (result.affected) {
      const fixed = events
        .filter((event) => event.kind === "fixed" && event.parsed !== null)
        .filter((event) => scheme.compare(event.parsed as ParsedVersion, installed) > 0)
        .sort((a, b) => scheme.compare(a.parsed as ParsedVersion, b.parsed as ParsedVersion))
        .map((event) => event.version);
      return { verdict: "affected", range: result.range, fixed: [...new Set(fixed)], via: "range" };
    }
  }
  if (unknownReason !== null) return { verdict: "unknown", reason: unknownReason };
  return { verdict: "not-affected" };
}
