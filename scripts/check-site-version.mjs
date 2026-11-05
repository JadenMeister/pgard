// Fails when the landing page's hand-written version labels drift from the code (#493):
//  - the hero `state-released` label (`vX.Y.Z`) and the `rules list` sample header
//    (`pgard X.Y.Z - detection criteria …`) must equal `packaging/pgard/package.json` `version`;
//  - the detection-criteria string in that header must equal `RULE_CRITERIA_VERSION`.
// The hidden `state-unreleased` text ("v0.1.0 not published yet", see site/style.css: it is
// `display: none` once <html data-released="true">) is deliberately not checked: it describes a
// state before the first release, not the current version. A label that cannot be found is an
// error, so a markup change cannot silently disable the check. Plain Node, no dependencies.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SITE_FILES = ["site/index.html", "site/ko/index.html"];
const SEMVER = String.raw`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?`;
const HERO_LABEL = new RegExp(String.raw`<span class="state-released">v(${SEMVER})</span>`, "g");
const SAMPLE_HEADER = new RegExp(
  String.raw`<b>pgard (${SEMVER}) - detection criteria ([0-9A-Za-z.-]+)</b>`,
  "g",
);

/** Reads `RULE_CRITERIA_VERSION` from the rules list source. */
export function readCriteriaVersion(source) {
  const match = /export const RULE_CRITERIA_VERSION = "([^"]+)"/.exec(source);
  if (!match)
    throw new Error("RULE_CRITERIA_VERSION not found in apps/cli/src/commands/rules/list.ts");
  return match[1];
}

/**
 * Returns a list of problems (empty when the page is consistent).
 * @param {string} file name used in messages
 * @param {string} html page source
 * @param {{ version: string, criteria: string }} expected
 */
export function checkSitePage(file, html, expected) {
  const problems = [];
  const hero = [...html.matchAll(HERO_LABEL)];
  if (hero.length !== 1) {
    problems.push(
      `${file}: expected exactly one hero label <span class="state-released">vX.Y.Z</span>, found ${hero.length}`,
    );
  } else if (hero[0][1] !== expected.version) {
    problems.push(`${file}: hero label says v${hero[0][1]}, expected v${expected.version}`);
  }
  const header = [...html.matchAll(SAMPLE_HEADER)];
  if (header.length === 0) {
    problems.push(`${file}: no sample header <b>pgard X.Y.Z - detection criteria …</b> found`);
  }
  for (const [, version, criteria] of header) {
    if (version !== expected.version) {
      problems.push(`${file}: sample header says pgard ${version}, expected ${expected.version}`);
    }
    if (criteria !== expected.criteria) {
      problems.push(
        `${file}: sample header says detection criteria ${criteria}, expected ${expected.criteria}`,
      );
    }
  }
  return problems;
}

/** Checks every site page against the files in the repository at `repoRoot`. */
export function checkSite(repoRoot = root) {
  const read = (rel) => readFileSync(path.join(repoRoot, rel), "utf8");
  const { version } = JSON.parse(read("packaging/pgard/package.json"));
  const criteria = readCriteriaVersion(read("apps/cli/src/commands/rules/list.ts"));
  return SITE_FILES.flatMap((file) => checkSitePage(file, read(file), { version, criteria }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const problems = checkSite();
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    console.error(
      "Update the site labels to match packaging/pgard/package.json and RULE_CRITERIA_VERSION.",
    );
    process.exit(1);
  }
  console.log("Site version labels match the package version and the rule criteria version.");
}
