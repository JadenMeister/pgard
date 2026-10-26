import type { Ecosystem } from "../types.js";

/**
 * What PGARD keeps of an OSV record: enough to match a package + version later, nothing else
 * (no details text, references or credits). One JSON object per line in the stored files.
 */
export interface ReducedAdvisory {
  id: string;
  aliases?: string[];
  modified: string;
  withdrawn?: string;
  summary?: string;
  /** CVSS vectors as published (`{type, score}`), and the database's own label if any. */
  severity?: { type: string; score: string }[];
  label?: string;
  affected: {
    name: string;
    versions?: string[];
    ranges?: { type: string; events: Record<string, string>[] }[];
  }[];
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

export function isMalwareId(id: string): boolean {
  return id.startsWith("MAL-");
}

/** Returns `null` when the record has no id/modified or no affected package of `ecosystem`. */
export function reduceAdvisory(raw: unknown, ecosystem: Ecosystem): ReducedAdvisory | null {
  if (!isObject(raw)) return null;
  const id = raw["id"];
  const modified = raw["modified"];
  if (typeof id !== "string" || id === "" || typeof modified !== "string") return null;
  const affected: ReducedAdvisory["affected"] = [];
  for (const item of Array.isArray(raw["affected"]) ? raw["affected"] : []) {
    if (!isObject(item) || !isObject(item["package"])) continue;
    const pkg = item["package"];
    if (pkg["ecosystem"] !== ecosystem || typeof pkg["name"] !== "string") continue;
    const entry: ReducedAdvisory["affected"][number] = { name: pkg["name"] };
    const versions = strings(item["versions"]);
    if (versions.length > 0) entry.versions = versions;
    const ranges: NonNullable<ReducedAdvisory["affected"][number]["ranges"]> = [];
    for (const range of Array.isArray(item["ranges"]) ? item["ranges"] : []) {
      if (!isObject(range) || typeof range["type"] !== "string") continue;
      const events: Record<string, string>[] = [];
      for (const event of Array.isArray(range["events"]) ? range["events"] : []) {
        if (!isObject(event)) continue;
        // No prototype: an event key such as `__proto__` stays a plain own property.
        const kept: Record<string, string> = Object.create(null) as Record<string, string>;
        for (const [key, value] of Object.entries(event)) {
          if (typeof value === "string") kept[key] = value;
        }
        events.push(kept);
      }
      ranges.push({ type: range["type"], events });
    }
    if (ranges.length > 0) entry.ranges = ranges;
    affected.push(entry);
  }
  if (affected.length === 0) return null;
  const reduced: ReducedAdvisory = { id, modified, affected };
  const aliases = strings(raw["aliases"]);
  if (aliases.length > 0) reduced.aliases = aliases;
  if (typeof raw["withdrawn"] === "string") reduced.withdrawn = raw["withdrawn"];
  if (!isMalwareId(id)) {
    if (typeof raw["summary"] === "string") reduced.summary = raw["summary"].slice(0, 300);
    const severity: { type: string; score: string }[] = [];
    for (const item of Array.isArray(raw["severity"]) ? raw["severity"] : []) {
      if (isObject(item) && typeof item["type"] === "string" && typeof item["score"] === "string") {
        severity.push({ type: item["type"], score: item["score"] });
      }
    }
    if (severity.length > 0) reduced.severity = severity;
    const database = raw["database_specific"];
    if (isObject(database) && typeof database["severity"] === "string") {
      reduced.label = database["severity"];
    }
  }
  return reduced;
}
