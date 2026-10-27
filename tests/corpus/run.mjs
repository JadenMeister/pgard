// Accuracy corpus runner: `npm run corpus` (write RESULTS.md) or `npm run corpus:check` (CI).
//
// Source rules: every file under tests/corpus/<RULE-ID>/{positive,negative}/ is copied alone into
// a fresh temporary project and scanned with scanSourceCode. The copy sits at the project root
// under its own name, so the path-based test/fixture/vendored labelling (which would otherwise
// see `tests/corpus/...`) never applies and nothing is demoted or hidden.
// History rules: history-cases.mjs describes throwaway git repositories built here.
// Web rules: web-cases.mjs describes loopback servers started here.
//
// Confidence: a rule fires on a sample at some confidence. A positive sample is found at any
// confidence. A negative sample must stay silent (`expect=none`), unless its header says
// `expect=low`: it is safe only through something the rules recognise but cannot prove (a guard,
// an allowlist table, a constant), so its own rule MUST report a finding capped at low confidence.
// Silence there fails the check (demotion regressed to hiding), and so does a medium or high
// finding (counted as a false positive).
// The report also gives precision counting only medium and high confidence findings.
//
// Labels are the truth. A rule is judged per sample: predicted = the rule reported a finding on
// that sample, expected = the sample's label lists the rule. Every disagreement (a miss or a false
// positive) must be declared with a reason (`known=` header / `known:` field), and the declared
// set must match the observed set exactly, so a regression and an unannounced fix both fail.
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HISTORY_RULES, scanGitHistory } from "@pgard/git-history";
import { scanLocalWeb, WEB_RULE_IDS } from "@pgard/http-local";
import { scanSourceCode, SOURCE_RULES } from "@pgard/source-analysis";
import { HISTORY_CASES } from "./history-cases.mjs";
import { HARDENED, WEB_CASES } from "./web-cases.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const RESULTS_PATH = path.join(here, "RESULTS.md");
const THRESHOLDS_PATH = path.join(here, "thresholds.json");
const isCheck = process.argv.includes("--check");

const problems = [];
const fail = (message) => problems.push(message);

// ---------------------------------------------------------------- samples

/** Parses `corpus: expect=A,B; known=miss:RULE:reason; known=fp:RULE:reason` from a header line. */
function parseHeader(line, label) {
  const match = /corpus:\s*(.*?)(?:\s*-->)?\s*$/.exec(line);
  if (match === null) {
    fail(`${label}: the first line must be a "corpus:" header comment`);
    return { expect: [], known: [], low: false };
  }
  const expect = [];
  const known = [];
  let low = false;
  let sawExpect = false;
  for (const part of match[1].split(";")) {
    const field = part.trim();
    if (field === "") continue;
    const [key, ...rest] = field.split("=");
    const value = rest.join("=").trim();
    if (key === "expect") {
      sawExpect = true;
      if (value === "low") low = true;
      else if (value !== "none") expect.push(...value.split(",").map((id) => id.trim()));
    } else if (key === "known") {
      const [type, rule, ...reason] = value.split(":");
      if ((type !== "miss" && type !== "fp") || !rule || reason.join(":").trim() === "") {
        fail(`${label}: known= must be miss|fp:RULE-ID:reason`);
      } else {
        known.push({ type, rule, reason: reason.join(":").trim() });
      }
    } else {
      fail(`${label}: unknown header field "${key}"`);
    }
  }
  if (!sawExpect) fail(`${label}: header needs expect=<ids|none>`);
  return { expect, known, low };
}

function loadSourceSamples() {
  const samples = [];
  for (const rule of readdirSync(here, { withFileTypes: true })) {
    if (!rule.isDirectory()) continue;
    for (const kind of ["positive", "negative"]) {
      const dir = path.join(here, rule.name, kind);
      let names;
      try {
        names = readdirSync(dir).sort();
      } catch {
        fail(`${rule.name}: missing ${kind}/ directory`);
        continue;
      }
      for (const name of names) {
        const file = path.join(dir, name);
        const label = `${rule.name}/${kind}/${name}`;
        const first = readFileSync(file, "utf8").split("\n", 1)[0];
        const { expect, known, low } = parseHeader(first, label);
        if (low && kind !== "negative") fail(`${label}: expect=low is for negative samples`);
        if (kind === "positive" && !expect.includes(rule.name)) {
          fail(`${label}: a positive sample must expect ${rule.name}`);
        }
        if (kind === "negative" && expect.includes(rule.name)) {
          fail(`${label}: a negative sample must not expect ${rule.name}`);
        }
        samples.push({
          domain: "source",
          rule: rule.name,
          kind,
          id: label,
          file,
          name,
          expect,
          known,
          low,
        });
      }
    }
  }
  return samples;
}

// ---------------------------------------------------------------- scanners

async function scanSource(sample) {
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-corpus-")));
  try {
    // Header line stays: it is a comment in every sample language.
    copyFileSync(sample.file, path.join(root, sample.name));
    const output = await scanSourceCode(root);
    // rule -> confidences of its findings on this sample
    const found = new Map();
    for (const finding of output.findings) {
      found.set(finding.ruleId, [...(found.get(finding.ruleId) ?? []), finding.confidence]);
    }
    return found;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function runGit(cwd, args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "",
      // Windows needs these for git to start and resolve its profile.
      ...Object.fromEntries(
        ["SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP", "USERPROFILE"]
          .filter((name) => process.env[name] !== undefined)
          .map((name) => [name, process.env[name]]),
      ),
      HOME: cwd,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
  });
}

async function scanHistoryCase(testCase) {
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-corpus-git-")));
  try {
    runGit(root, ["init", "-q", "-b", "main"]);
    runGit(root, ["config", "commit.gpgsign", "false"]);
    const write = (relative, content) => {
      const target = path.join(root, relative);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, content);
    };
    testCase.commits.forEach((commit, index) => {
      for (const [file, content] of Object.entries(commit.files ?? {})) write(file, content);
      for (const file of commit.remove ?? []) runGit(root, ["rm", "-q", "--", file]);
      runGit(root, ["add", "-A"]);
      runGit(root, [
        "-c",
        "user.name=Corpus",
        "-c",
        "user.email=corpus@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        `commit ${index}`,
      ]);
    });
    for (const [file, content] of Object.entries(testCase.untracked ?? {})) write(file, content);
    const output = await scanGitHistory(root);
    const confidences = new Map();
    for (const finding of output.findings) {
      confidences.set(finding.ruleId, [
        ...(confidences.get(finding.ruleId) ?? []),
        finding.confidence,
      ]);
    }
    return confidences;
  } finally {
    rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

async function scanWebCase(testCase) {
  const rootHeaders = { ...HARDENED };
  for (const [name, value] of Object.entries(testCase.headers ?? {})) {
    if (value === null) delete rootHeaders[name];
    else rootHeaders[name] = value;
  }
  const rootBody = testCase.rootBody ?? "<title>Corpus</title><p>hello</p>";
  const server = http.createServer((request, response) => {
    const url = (request.url ?? "/").split("?")[0];
    const origin = request.headers.origin;
    const corsHeaders =
      typeof origin === "string" && testCase.cors ? (testCase.cors(origin) ?? {}) : {};
    if (url === "/") {
      if (testCase.rootRedirect) {
        response.writeHead(302, { location: "http://example.com/" }).end();
        return;
      }
      response.writeHead(200, {
        ...rootHeaders,
        ...corsHeaders,
        ...(testCase.cookies ? { "set-cookie": testCase.cookies } : {}),
      });
      response.end(rootBody);
      return;
    }
    const route = testCase.routes?.[url];
    if (route) {
      response.writeHead(route.status, { ...(route.headers ?? {}), ...corsHeaders });
      response.end(route.body ?? "");
      return;
    }
    if (testCase.fallbackHtml) {
      response.writeHead(200, { "content-type": "text/html" }).end("<title>App</title>");
      return;
    }
    response.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const output = await scanLocalWeb(
      { port, origin: `http://127.0.0.1:${port}`, title: null, confirmedByUser: true },
      {},
    );
    return new Set(output.findings.map((finding) => finding.ruleId));
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

// ---------------------------------------------------------------- build the full sample list

const samples = loadSourceSamples();
for (const testCase of HISTORY_CASES) {
  samples.push({
    domain: "history",
    rule: testCase.rule,
    kind: testCase.kind,
    id: `history/${testCase.name}`,
    expect: testCase.expect,
    known: testCase.known ?? [],
    low: testCase.low === true,
    run: () => scanHistoryCase(testCase),
  });
}
for (const testCase of WEB_CASES) {
  samples.push({
    domain: "web",
    rule: testCase.expect[0] ?? "(none)",
    kind: testCase.expect.length > 0 ? "positive" : "negative",
    id: `web/${testCase.name}`,
    expect: testCase.expect,
    known: testCase.known ?? [],
    run: () => scanWebCase(testCase),
  });
}
for (const sample of samples) {
  if (sample.domain === "source") sample.run = () => scanSource(sample);
}

const RULES = {
  source: SOURCE_RULES.map((rule) => rule.id),
  history: HISTORY_RULES.map((rule) => rule.id),
  web: [...WEB_RULE_IDS],
};

// ---------------------------------------------------------------- run

const stats = new Map(); // rule -> { domain, tp, fp, fn, tn, tpStrong, fpStrong }
for (const [domain, ids] of Object.entries(RULES)) {
  for (const id of ids)
    stats.set(id, { domain, tp: 0, fp: 0, fn: 0, tn: 0, tpStrong: 0, fpStrong: 0 });
}
const deviations = []; // { sample, rule, type, reason | null }

for (const sample of samples) {
  const raw = await sample.run();
  // Web rules have no confidence levels (every finding counts as high); history cases report theirs.
  const found = raw instanceof Map ? raw : new Map([...raw].map((id) => [id, ["high"]]));
  const expectLow = sample.low === true;
  const universe = RULES[sample.domain];
  for (const rule of sample.expect) {
    if (!universe.includes(rule))
      fail(`${sample.id}: expects unknown ${sample.domain} rule ${rule}`);
  }
  for (const rule of universe) {
    const expected = sample.expect.includes(rule);
    const confidences = found.get(rule) ?? [];
    const strong = confidences.some((confidence) => confidence !== "low");
    // `expect=low`: the sample's own rule must report, at low confidence only.
    const lowExpected = expectLow && rule === sample.rule;
    if (lowExpected && confidences.length === 0)
      fail(
        `${sample.id}: expected a low-confidence ${rule} finding but the rule is silent (demotion regressed to hiding the finding)`,
      );
    const predicted = lowExpected ? strong : confidences.length > 0;
    const entry = stats.get(rule);
    if (expected && strong) entry.tpStrong += 1;
    if (!expected && strong) entry.fpStrong += 1;
    if (expected && predicted) entry.tp += 1;
    else if (!expected && predicted) entry.fp += 1;
    else if (expected && !predicted) entry.fn += 1;
    else entry.tn += 1;
    if (expected !== predicted) {
      deviations.push({ sample, rule, type: expected ? "miss" : "fp" });
    }
  }
  // Every declared expected failure must be a real, current deviation (and vice versa).
  for (const known of sample.known) {
    const hit = deviations.some(
      (d) => d.sample === sample && d.rule === known.rule && d.type === known.type,
    );
    if (!hit) {
      fail(
        `${sample.id}: declared known ${known.type} for ${known.rule} no longer happens; remove the known= entry (the rule improved) and raise the threshold`,
      );
    }
  }
}
for (const deviation of deviations) {
  const declared = deviation.sample.known.find(
    (known) => known.rule === deviation.rule && known.type === deviation.type,
  );
  if (declared) deviation.reason = declared.reason;
  else {
    deviation.reason = null;
    fail(
      `${deviation.sample.id}: unexpected ${deviation.type === "miss" ? "miss (false negative)" : "false positive"} for ${deviation.rule}; fix the rule, or record it with known=${deviation.type}:${deviation.rule}:<reason>`,
    );
  }
}

// ---------------------------------------------------------------- report

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const ratio = (numerator, denominator) => (denominator === 0 ? null : numerator / denominator);
const pct = (value) => (value === null ? "n/a" : `${(value * 100).toFixed(1)}%`);
const rows = [...stats.entries()].map(([rule, s]) => ({
  rule,
  ...s,
  precision: ratio(s.tp, s.tp + s.fp),
  recall: ratio(s.tp, s.tp + s.fn),
  precisionStrong: ratio(s.tpStrong, s.tpStrong + s.fpStrong),
}));

let thresholds = { rules: {} };
if (process.argv.includes("--update-thresholds")) {
  // Records the current numbers as the new floor. Use it only on purpose, in a reviewed change:
  // lowering a threshold hides a regression.
  const floor = (value) => Math.floor((value ?? 0) * 1000) / 1000;
  thresholds = {
    rules: Object.fromEntries(
      rows.map((row) => [
        row.rule,
        {
          precision: floor(row.precision),
          recall: floor(row.recall),
          precisionMedium: floor(row.precisionStrong),
        },
      ]),
    ),
  };
  writeFileSync(THRESHOLDS_PATH, `${JSON.stringify(thresholds, null, 2)}\n`);
  console.log("Wrote tests/corpus/thresholds.json");
}
try {
  thresholds = JSON.parse(readFileSync(THRESHOLDS_PATH, "utf8"));
} catch {
  fail("tests/corpus/thresholds.json is missing or invalid");
}
for (const row of rows) {
  const limit = thresholds.rules?.[row.rule];
  if (!limit) {
    fail(`${row.rule}: no entry in thresholds.json`);
    continue;
  }
  if (row.tp + row.fn === 0) {
    fail(`${row.rule}: the corpus has no positive sample for this rule, so recall is undefined`);
    continue;
  }
  if ((row.precision ?? 0) < limit.precision) {
    fail(
      `${row.rule}: precision ${pct(row.precision)} is below the threshold ${pct(limit.precision)}`,
    );
  }
  if ((row.precisionStrong ?? 0) < (limit.precisionMedium ?? 0)) {
    fail(
      `${row.rule}: precision at medium+ confidence ${pct(row.precisionStrong)} is below the threshold ${pct(limit.precisionMedium)}`,
    );
  }
  if ((row.recall ?? 0) < limit.recall) {
    fail(`${row.rule}: recall ${pct(row.recall)} is below the threshold ${pct(limit.recall)}`);
  }
}

const SECTION_TITLES = {
  source: "Source rules (scanSourceCode)",
  history: "History rules (scanGitHistory on generated git repositories)",
  web: "Web rules (scanLocalWeb against loopback servers)",
};
const lines = [
  "# Accuracy corpus results",
  "",
  "Generated by `npm run corpus`; do not edit by hand. CI fails when this file is out of date.",
  "",
  "The corpus is small and written by the PGARD authors, so these numbers describe how the rules",
  "behave on the cases we thought of, not how they behave on your code. Precision and recall here",
  "are measured per rule over every sample of the same kind (a finding from another rule on a",
  "sample that does not list it counts as a false positive for that other rule).",
  "",
  "TP: expected and reported. FP: reported but not expected. FN: expected but not reported.",
  "TN: neither. Precision = TP / (TP + FP). Recall = TP / (TP + FN).",
  "",
  "Confidence: a finding at any confidence counts for recall. A safe sample that is only safe through",
  "a recognised guard, allowlist table or constant is labelled `expect=low`: its rule must report a",
  "finding capped at low confidence (counted as TN); silence or a medium/high finding fails the",
  "check, because guards lower confidence and never hide a finding. Precision (medium+) counts only",
  "medium and high confidence findings, on every sample.",
  "",
];
for (const domain of ["source", "history", "web"]) {
  const domainSamples = samples.filter((sample) => sample.domain === domain);
  lines.push(`## ${SECTION_TITLES[domain]}`, "");
  lines.push(`${domainSamples.length} samples.`, "");
  lines.push(
    "| Rule | TP | FP | FN | TN | Precision | Recall | Precision (medium+) |",
    "| --- | --: | --: | --: | --: | --: | --: | --: |",
  );
  for (const row of rows.filter((candidate) => candidate.domain === domain)) {
    lines.push(
      `| ${row.rule} | ${row.tp} | ${row.fp} | ${row.fn} | ${row.tn} | ${pct(row.precision)} | ${pct(row.recall)} | ${pct(row.precisionStrong)} |`,
    );
  }
  lines.push("");
}
lines.push("## Known misses and false positives", "");
lines.push(
  "Each entry is a sample the current rules get wrong. They are kept on purpose and listed with a",
  "reason; fixing a rule should remove its entry here and raise its threshold.",
  "",
);
if (deviations.length === 0) {
  lines.push("None.", "");
} else {
  lines.push("| Rule | Kind | Sample | Reason |", "| --- | --- | --- | --- |");
  for (const deviation of deviations.sort(
    (a, b) => compare(a.rule, b.rule) || compare(a.sample.id, b.sample.id),
  )) {
    lines.push(
      `| ${deviation.rule} | ${deviation.type === "miss" ? "miss (FN)" : "false positive (FP)"} | \`${deviation.sample.id}\` | ${deviation.reason ?? "UNRECORDED"} |`,
    );
  }
  lines.push("");
}
const report = `${lines.join("\n")}\n`.replace(/\n{3,}$/, "\n");

// Console summary.
const width = Math.max(...rows.map((row) => row.rule.length));
for (const domain of ["source", "history", "web"]) {
  console.log(`\n${SECTION_TITLES[domain]}`);
  console.log(`${"rule".padEnd(width)}  TP  FP  FN  TN  precision  recall`);
  for (const row of rows.filter((candidate) => candidate.domain === domain)) {
    console.log(
      `${row.rule.padEnd(width)}  ${String(row.tp).padStart(2)}  ${String(row.fp).padStart(2)}  ${String(row.fn).padStart(2)}  ${String(row.tn).padStart(2)}  ${pct(row.precision).padStart(9)}  ${pct(row.recall).padStart(6)}`,
    );
  }
}
console.log(`\n${samples.length} samples, ${deviations.length} known deviations.`);

let committed = null;
try {
  committed = readFileSync(RESULTS_PATH, "utf8");
} catch {
  committed = null;
}
if (isCheck) {
  if (committed !== report) {
    fail("tests/corpus/RESULTS.md is out of date: run `npm run corpus` and commit the result");
  }
} else if (committed !== report) {
  writeFileSync(RESULTS_PATH, report);
  console.log("Wrote tests/corpus/RESULTS.md");
}

if (problems.length > 0) {
  console.error(
    `\nCorpus check failed:\n${problems.map((problem) => `  - ${problem}`).join("\n")}`,
  );
  process.exit(1);
}
