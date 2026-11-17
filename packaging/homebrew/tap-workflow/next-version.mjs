#!/usr/bin/env node
// Decides whether the tap workflow should open an update PR, and for which version.
// Pure function `decideUpdate` plus a small CLI that prints `key=value` lines for $GITHUB_OUTPUT:
//   node next-version.mjs --current 0.2.0 --latest 0.3.0 [--requested 0.3.0] --time-file time.json [--now ISO]
// Output: `version=<x.y.z>` when an update should be opened (otherwise an empty `version=`),
// and `reason=<text>` always. Exit 2 for invalid input (the workflow then fails and changes nothing).
// Only plain x.y.z versions are accepted; a pre-release (anything with `-`) is ignored, not an error.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
// Homebrew runs npm with --min-release-age=1 and refuses a version younger than a day.
export const MIN_AGE_MS = 24 * 60 * 60 * 1000;

function isPlain(value) {
  return typeof value === "string" && VERSION_PATTERN.test(value);
}

/** -1 when a < b, 0 when equal, 1 when a > b. Both must be plain x.y.z. */
export function compareVersions(a, b) {
  if (!isPlain(a) || !isPlain(b)) throw new Error(`not a plain x.y.z version: ${a} / ${b}`);
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
  }
  return 0;
}

/**
 * @param {{ current: string, latest: string, requested?: string, time: unknown, now: number }} input
 * @returns {{ version: string | null, reason: string }}
 */
export function decideUpdate({ current, latest, requested, time, now }) {
  if (!isPlain(current)) throw new Error(`the formula version is not x.y.z: ${String(current)}`);
  if (typeof now !== "number" || Number.isNaN(now)) throw new Error("now must be a number");
  // Nothing outside this alphabet may reach `reason=`: a newline would inject an output line.
  for (const value of [latest, requested]) {
    if (value !== undefined && !/^[0-9A-Za-z.-]+$/.test(String(value))) {
      throw new Error("a version contains characters outside [0-9A-Za-z.-]");
    }
  }
  const wanted = requested ? requested : latest;
  if (typeof wanted === "string" && wanted.includes("-")) {
    return { version: null, reason: `${wanted} is a pre-release; ignored` };
  }
  if (!isPlain(wanted)) throw new Error(`not a version: ${String(wanted)}`);
  if (compareVersions(wanted, current) <= 0) {
    return { version: null, reason: `${wanted} is not newer than the formula's ${current}` };
  }
  if (typeof time !== "object" || time === null || Array.isArray(time)) {
    throw new Error("the registry time document is not an object");
  }
  const published = /** @type {Record<string, unknown>} */ (time)[wanted];
  const publishedAt = typeof published === "string" ? Date.parse(published) : Number.NaN;
  if (Number.isNaN(publishedAt)) throw new Error(`no publish time for ${wanted} in the registry`);
  if (now - publishedAt < MIN_AGE_MS) {
    return {
      version: null,
      reason: `${wanted} was published less than 24 hours ago; Homebrew refuses it yet`,
    };
  }
  return { version: wanted, reason: `${current} -> ${wanted}` };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!key?.startsWith("--") || i + 1 >= argv.length)
      throw new Error(`bad arguments near ${key}`);
    out[key.slice(2)] = argv[i + 1];
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const requested = args.requested ?? "";
  if (requested !== "" && !isPlain(requested)) {
    throw new Error("the requested version is not x.y.z");
  }
  if (!args["time-file"]) throw new Error("--time-file is required");
  const now = args.now ? Date.parse(args.now) : Date.now();
  const result = decideUpdate({
    current: args.current,
    latest: args.latest,
    requested: requested || undefined,
    time: JSON.parse(readFileSync(args["time-file"], "utf8")),
    now,
  });
  process.stdout.write(`version=${result.version ?? ""}\nreason=${result.reason}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(2);
  }
}
