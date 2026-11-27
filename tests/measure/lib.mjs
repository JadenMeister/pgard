// Pure logic of the real-repository recall measurement: validation, hit matching, fix check and
// aggregation. No I/O, so it is unit tested offline (lib.test.ts). See README.md for the hit rule.
import { familiesForCwes, ruleInFamily } from "./cwe-families.mjs";

/** A finding must sit this many lines from an expected range to count as a (strict) hit. */
export const LINE_TOLERANCE = 5;

const normalize = (file) =>
  String(file ?? "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "");

// ---------------------------------------------------------------- input validation

export const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
export const SHA_PATTERN = /^[0-9a-f]{40}$/;

/** `owner/name` with safe characters only (no `.`/`..` parts, no slashes beyond the one). */
export const validRepo = (repo) =>
  typeof repo === "string" &&
  REPO_PATTERN.test(repo) &&
  repo.split("/").every((part) => part !== "." && part !== "..");

export const validSha = (sha) => typeof sha === "string" && SHA_PATTERN.test(sha);

/** A single safe folder name for a repository's cache (every slash replaced). */
export const cacheDirName = (repo) => `${repo.replace(/[^A-Za-z0-9_.-]/g, "__")}.git`;

/** A positive integer option value, or null. */
export const positiveInt = (value) => (/^[1-9]\d{0,5}$/.test(String(value)) ? Number(value) : null);

// ---------------------------------------------------------------- matching

/**
 * Judges one case from the findings of a scan of its vulnCommit tree.
 * `findings`: [{ ruleId, path, line }]. Returns { status: hit|loose|miss, matchedRules, ... }.
 * hit: a same-family finding in an expected file within LINE_TOLERANCE lines of an expected range.
 * loose: a same-family finding in an expected file, but not near. miss: neither.
 */
export function matchCase(testCase, findings) {
  const families = familiesForCwes(testCase.cwe);
  const inFamily = (finding) => families.some((family) => ruleInFamily(finding.ruleId, family));
  const expectedFiles = new Set(testCase.expect.map((range) => normalize(range.file)));
  const inFile = findings.filter((finding) => expectedFiles.has(normalize(finding.path)));
  const sameFamily = inFile.filter(inFamily);
  const hits = sameFamily.filter((finding) => nearExpected(testCase, finding));
  const matched = hits.length > 0 ? hits : sameFamily;
  return {
    status: hits.length > 0 ? "hit" : sameFamily.length > 0 ? "loose" : "miss",
    matchedRules: [...new Set(matched.map((finding) => finding.ruleId))].sort(),
    sameFamilyInFile: sameFamily.length,
    anyFindingsInFile: inFile.length,
  };
}

function nearExpected(testCase, finding) {
  return testCase.expect.some(
    (range) =>
      normalize(range.file) === normalize(finding.path) &&
      typeof finding.line === "number" &&
      finding.line >= range.startLine - LINE_TOLERANCE &&
      finding.line <= range.endLine + LINE_TOLERANCE,
  );
}

/** Coverage areas that are not a full run: partial or not tested (not_selected is not a gap). */
export const gapAreas = (coverage) =>
  coverage
    // deps:* is off by design (no advisory data is given), so it is not a gap of the source scan.
    .filter(
      (c) => (c.status === "partial" || c.status === "not_tested") && !c.area.startsWith("deps:"),
    )
    .map((c) => c.area);

/**
 * The full judgement of a case: matchCase plus what the scan's own coverage says.
 * - no-rule: PGARD has no rule for the case's CWE (never a miss of an existing rule).
 * - not-tested: nothing found and a language area (`source:<language>`) or an area carrying a rule of the family was
 *   not tested, so silence proves nothing.
 * - unsupported-language: nothing found and no analyzer that carries a rule of the family ran on
 *   this repository (for example a language PGARD does not read).
 * `partial` is true for any partial or not_tested area (never for not_selected).
 */
export function judgeCase(testCase, findings, coverage) {
  const families = familiesForCwes(testCase.cwe);
  const partialAreas = gapAreas(coverage);
  if (families.length === 0) {
    return {
      status: "no-rule",
      matchedRules: [],
      sameFamilyInFile: 0,
      anyFindingsInFile: 0,
      partial: false,
      partialAreas: [],
    };
  }
  const result = {
    ...matchCase(testCase, findings),
    partial: partialAreas.length > 0,
    partialAreas,
  };
  if (result.status !== "miss") return result;
  const carriesFamilyRule = (c) =>
    c.ruleIds.some((id) => families.some((family) => ruleInFamily(id, family)));
  const notTested = coverage.some(
    (c) => c.status === "not_tested" && (carriesFamilyRule(c) || /^source:[a-z]+$/.test(c.area)),
  );
  if (notTested) return { ...result, status: "not-tested" };
  const ran = coverage.some(
    (c) => (c.status === "completed" || c.status === "partial") && carriesFamilyRule(c),
  );
  return ran ? result : { ...result, status: "unsupported-language" };
}

/**
 * Fix check, for a hit: the finding is "gone" when the fixed tree has no finding of the matched
 * rules near an expected range (old-file lines, so a fix that moves code can read as gone).
 * null (not comparable) when the fixed tree no longer has any expected file or the case is not a hit.
 */
export function fixCheck(testCase, matchedRules, fixFindings, fixHasExpectedFile) {
  if (!fixHasExpectedFile) return { fixGone: null, fixNote: "expected file removed at the fix" };
  if (matchedRules.length === 0)
    return { fixGone: null, fixNote: "no near-range finding to compare" };
  const still = fixFindings.some(
    (finding) => matchedRules.includes(finding.ruleId) && nearExpected(testCase, finding),
  );
  return { fixGone: !still, fixNote: null };
}

// ---------------------------------------------------------------- aggregation

const pct = (part, total) => (total === 0 ? "n/a" : `${((100 * part) / total).toFixed(1)}%`);

/**
 * Counts of one group. Recall is over the cases that have a rule (n minus no-rule): not-tested,
 * errors and unsupported languages stay in the denominator, so recall is never inflated.
 */
export function tally(results) {
  const count = (status) => results.filter((result) => result.status === status).length;
  const hit = count("hit");
  const loose = count("loose");
  const miss = count("miss");
  const notTested = count("not-tested");
  const noRule = count("no-rule");
  const n = results.length;
  const ruleN = n - noRule;
  return {
    n,
    ruleN,
    hit,
    loose,
    miss,
    notTested,
    noRule,
    unmeasured: n - hit - loose - miss - notTested - noRule,
    partial: results.filter((result) => result.partial).length,
    hitPct: pct(hit, ruleN),
    loosePct: pct(hit + loose, ruleN),
  };
}

function groupBy(results, keys) {
  const groups = new Map();
  for (const result of results) {
    for (const key of new Set(keys(result))) groups.set(key, [...(groups.get(key) ?? []), result]);
  }
  return [...groups.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

const SUBSETS = [
  ["all", () => true],
  ["non-doubtful", (result) => !result.doubtful],
  ["in-scope", (result) => result.inScope],
];

const familyKeys = (result) => {
  const names = familiesForCwes(result.cwe).map((entry) => entry.family);
  return names.length > 0 ? names : ["(no rule)"];
};

function table(title, results, keys) {
  const lines = [
    `### ${title}`,
    "",
    "| Group | n | with rule | hit | hit % | hit+loose % | miss | not-tested | no-rule | not measured | partial scans |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
  ];
  for (const [key, group] of groupBy(results, keys)) {
    const t = tally(group);
    lines.push(
      `| ${key} | ${t.n} | ${t.ruleN} | ${t.hit} | ${t.hitPct} | ${t.loosePct} | ${t.miss} | ${t.notTested} | ${t.noRule} | ${t.unmeasured} | ${t.partial} |`,
    );
  }
  return [...lines, ""];
}

/** The RESULTS-REAL.md text from a run's results (no per-case details, no thresholds). */
export function renderMarkdown(results, meta) {
  const lines = [
    "# Real-repository recall (measurement, not a gate)",
    "",
    "Generated by `npm run measure` (tests/measure/run.mjs); see README.md for the hit rule and caveats.",
    "There are no pass thresholds. `n` is shown everywhere: small groups are noise, not a rate.",
    "",
    `- Run: ${meta.date}, PGARD ${meta.version}, ${results.length} case(s)${meta.filter ? `, filter: ${meta.filter}` : ""}`,
    "- hit: a same-family finding within +-5 lines of an expected range. hit+loose: also a same-family finding in the expected file only.",
    "- Recall is over `with rule` (n minus no-rule). no-rule: PGARD has no rule for the CWE, so it is not a miss.",
    "- not-tested: nothing found and a relevant area was not tested; partial scans: any partial or not-tested area (a separate count, a hit can be in a partial scan).",
    "- not measured: fetch-error, scan-error or unsupported-language (they stay in the denominator, so recall is never inflated). A timeout is a scan-error.",
    "- Per-family rows can overlap: a case with CWEs of two families counts in both rows.",
    "",
  ];
  for (const [name, keep] of SUBSETS) {
    const subset = results.filter(keep);
    lines.push(`## ${name} (n=${subset.length})`, "");
    lines.push(...table("Per language", subset, (result) => [result.language]));
    lines.push(...table("Per CWE family", subset, familyKeys));
  }
  return `${lines.join("\n")}\n`.replace(/\n{3,}$/, "\n");
}
