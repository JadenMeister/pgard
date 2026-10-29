import { VIEWS, type View } from "../../app/views";
import type { FindingFilters } from "./filter-findings";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const STATUSES = ["confirmed", "suspected", "informational"] as const;
const SOURCES = ["code", "history", "web"] as const;
const MAX_VALUE_LENGTH = 200;

/** The query keys the dashboard reads and writes; any other key in the address is ignored. */
const KEYS = ["severity", "status", "source", "category", "rule", "area", "path", "q"] as const;

const oneOf = <T extends string>(allowed: readonly T[], value: string | null): T | null =>
  value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : null;

/** Free text (rule, area, path, search): bounded, without control characters. */
function cleanText(value: string | null): string | null {
  if (value === null) return null;
  let text = "";
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code >= 0x20 && code !== 0x7f) text += character;
  }
  text = text.slice(0, MAX_VALUE_LENGTH);
  return text === "" ? null : text;
}

/** A category id is `snake_case`; unknown ids simply match nothing. */
function cleanId(value: string | null): string | null {
  return value !== null && /^[a-z][a-z0-9_]{0,63}$/.test(value) ? value : null;
}

export interface ParsedHash {
  view: View;
  filters: FindingFilters;
}

/**
 * Reads `#<view>?severity=high&category=xss`: the part after `?` is the filter state. Values are
 * validated and unknown keys dropped, so nothing else in the fragment (a session token, say)
 * ever reaches state or is written back.
 */
export function parseHash(hash: string): ParsedHash {
  const body = hash.replace(/^#/, "");
  const at = body.indexOf("?");
  const name = at === -1 ? body : body.slice(0, at);
  const params = new URLSearchParams(at === -1 ? "" : body.slice(at + 1));
  const view = (VIEWS as readonly string[]).includes(name) ? (name as View) : "overview";
  const filters: FindingFilters = {
    severity: oneOf(SEVERITIES, params.get("severity")),
    status: oneOf(STATUSES, params.get("status")),
    source: oneOf(SOURCES, params.get("source")),
    category: cleanId(params.get("category")) as FindingFilters["category"],
    rule: cleanText(params.get("rule")),
    area: cleanText(params.get("area")),
    path: cleanText(params.get("path")),
    text: cleanText(params.get("q")) ?? "",
  };
  return { view, filters };
}

/** The filters as a query string without `?` (`severity=high&q=sql`); empty without filters. */
export function serializeFilters(filters: FindingFilters): string {
  const values: Record<(typeof KEYS)[number], string | null> = {
    severity: filters.severity,
    status: filters.status,
    source: filters.source,
    category: filters.category,
    rule: filters.rule,
    area: filters.area,
    path: filters.path,
    q: filters.text.trim() === "" ? null : filters.text,
  };
  const params = new URLSearchParams();
  for (const key of KEYS) {
    const value = values[key];
    if (value !== null) params.set(key, value.slice(0, MAX_VALUE_LENGTH));
  }
  return params.toString();
}

/** The fragment for a view and its filters: `#findings?severity=high`, or just `#findings`. */
export function buildHash(view: View, filters: FindingFilters): string {
  const query = serializeFilters(filters);
  return query === "" ? `#${view}` : `#${view}?${query}`;
}

/**
 * The canonical fragment for whatever the address holds, or "" when it names neither a view nor
 * a filter. Used when the session token is removed from the fragment: the token (and anything
 * else off the allow-list) is dropped, a valid view and filters are kept.
 */
export function canonicalHash(hash: string): string {
  const { view, filters } = parseHash(hash);
  const named = hash.replace(/^#/, "").split("?")[0];
  const query = serializeFilters(filters);
  if (named !== view && query === "") return "";
  return buildHash(view, filters);
}

export function hasActiveFilters(filters: FindingFilters): boolean {
  return serializeFilters(filters) !== "";
}
