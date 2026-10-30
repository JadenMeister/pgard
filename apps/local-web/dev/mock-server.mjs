// Dev-only preview of the dashboard with fixture data. Not part of the package (`files` is
// `dist` only) and never started by pgard: it serves the built client from dist/client with the
// real security headers and CSP, and answers /api/* from fixtures. No GitHub, no scan, no
// keychain, no real device code.
//
//   npm run build
//   node apps/local-web/dev/mock-server.mjs [port]
//   open http://127.0.0.1:<port>/#token=mockmockmockmockmockmockmockmock
//
// Pick a scenario with POST /__mock/scenario?name=<onboarding|blocked|running|results|empty>.
// The Trend view has its own scenarios, which keep the "results" scan and change only what
// GET /api/trend answers: trend (20 saved scans, some partial), trend-few (one saved scan),
// trend-off (the store is switched off), trend-unverified (not verified yet).
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { buildRuleTextCatalog, computeStandardsCoverage } from "@pgard/findings";
import { WEB_RULE_LIST } from "@pgard/http-local";
import { listSupportedRules } from "@pgard/scan-core";
import { applySecurityHeaders } from "../dist/server/middleware/security.js";

const port = Number(process.argv[2] ?? 4317);
const clientRoot = fileURLToPath(new URL("../dist/client/", import.meta.url));
const SCENARIOS = new Set(["onboarding", "blocked", "running", "results", "empty"]);
const TREND_SCENARIOS = new Set(["trend", "trend-few", "trend-off", "trend-unverified"]);
let scenario = process.env.PGARD_MOCK_SCENARIO ?? "results";
let trendScenario = "trend";

const rules = [
  ...listSupportedRules(),
  ...WEB_RULE_LIST.map((rule) => ({ id: rule.id, scope: "web", metadata: rule.metadata })),
];
const ruleTexts = Object.fromEntries(
  buildRuleTextCatalog([...listSupportedRules(), ...WEB_RULE_LIST]),
);

const CHECKS_ALLOWED = [
  ["repository", "passed", "acme/shop is a GitHub repository (origin remote)."],
  ["github_identity", "passed", "Signed in to GitHub as octo-dev."],
  ["owner_approval", "passed", "The PGARD GitHub App is installed for acme/shop."],
  ["current_access", "passed", "octo-dev has write access to acme/shop."],
  ["contribution", "passed", "octo-dev authored a merged pull request (#42)."],
];
const CHECKS_BLOCKED = [
  CHECKS_ALLOWED[0],
  CHECKS_ALLOWED[1],
  [
    "owner_approval",
    "failed",
    "The PGARD GitHub App is not installed for acme/shop, so the owner has not approved scans.",
  ],
  ["current_access", "passed", "octo-dev has write access to acme/shop."],
  ["contribution", "unverifiable", "Not checked because owner approval failed."],
];
const summary = (checks, decision) => ({
  decision,
  checks: checks.map(([id, status, reason]) => ({ id, status, reason })),
});

function authStatus() {
  const base = {
    status: "idle",
    deviceCode: null,
    summary: null,
    repo: null,
    message: null,
    storedSignIn: { status: "none" },
    remedy: null,
    accessNote: null,
    signInNotice: null,
    expiresAt: null,
    installWaitEndsAt: null,
  };
  if (scenario === "onboarding") return base;
  if (scenario === "blocked") {
    return {
      ...base,
      status: "done",
      repo: "acme/shop",
      storedSignIn: { status: "stored", login: "octo-dev" },
      summary: summary(CHECKS_BLOCKED, "blocked"),
      remedy: {
        kind: "install_app",
        missing: "installation",
        account: { login: "acme", type: "Organization" },
        url: "https://github.com/apps/pgard/installations/new",
        canApprove: "yes",
        unavailableReason: null,
      },
      installWaitEndsAt: Date.now() + 10 * 60 * 1000,
    };
  }
  return {
    ...base,
    status: "done",
    repo: "acme/shop",
    storedSignIn: { status: "stored", login: "octo-dev" },
    summary: summary(CHECKS_ALLOWED, "allowed"),
    expiresAt: Date.now() + 15 * 60 * 1000,
  };
}

function verifyStatus() {
  if (scenario !== "onboarding") return authStatus();
  // An obviously fake code: the preview never talks to GitHub.
  return {
    ...authStatus(),
    status: "running",
    deviceCode: {
      userCode: "MOCK-0000",
      verificationUri: "https://github.com/login/device",
      expiresIn: 900,
    },
  };
}

const PATHS = [
  "src/routes/orders.ts",
  "src/routes/users.ts",
  "src/db/query.ts",
  "src/api/payments/refund.ts",
  "server/app.js",
  "server/middleware/session.js",
  "app/controllers/admin_controller.rb",
  "services/billing/src/main/java/com/acme/billing/InvoiceService.java",
  "web/templates/profile.html",
  "config/production.yml",
  "scripts/deploy.sh",
  "src/lib/crypto.ts",
];
const SEVERITIES = ["critical", "high", "high", "medium", "medium", "medium", "low", "low", "info"];
const STATUSES = ["confirmed", "suspected", "suspected", "informational"];

function makeFindings(count) {
  const codeRules = listSupportedRules();
  const findings = [];
  for (let index = 0; index < count; index += 1) {
    const rule = codeRules[(index * 7) % codeRules.length];
    const severity = SEVERITIES[(index * 5) % SEVERITIES.length];
    const isHistory = index % 9 === 4;
    const path = PATHS[index % PATHS.length];
    findings.push({
      id: `f${index + 1}`,
      ruleId: rule.id,
      title: rule.title,
      category: rule.category,
      severity,
      status: STATUSES[index % STATUSES.length],
      confidence: ["high", "medium", "low"][index % 3],
      location: isHistory
        ? { kind: "commit", path, line: 10 + (index % 80), url: null, commit: "9f2c1e7ab03d55e1" }
        : { kind: "file", path, line: 10 + ((index * 13) % 400), url: null, commit: null },
      evidence:
        index % 2 === 0
          ? 'query("SELECT * FROM orders WHERE id = " + <request value>) (value redacted)'
          : 'token = "<redacted, 40 characters>" in a tracked file',
      impact: ruleTexts[rule.id].impact.en,
      recommendation: ruleTexts[rule.id].recommendation.en,
      references: { cwe: rule.cwe ?? [], owasp: rule.owasp ?? [], cve: [] },
      sources: [isHistory ? "history" : "code"],
    });
  }
  // A few in test code and in vendored code, so the separate groups show.
  for (let index = 0; index < Math.min(6, findings.length); index += 1) {
    findings.push({
      ...findings[index],
      id: `t${index}`,
      context: "test",
      confidence: "low",
      location: { ...findings[index].location, path: `test/fixtures/sample-${index}.ts` },
    });
  }
  for (let index = 0; index < (findings.length > 13 ? 3 : 0); index += 1) {
    findings.push({
      ...findings[index + 10],
      id: `v${index}`,
      context: "vendored",
      confidence: "low",
      location: { ...findings[index + 10].location, path: `vendor/legacy/lib-${index}.js` },
    });
  }
  return findings;
}

function makeResult(findingCount) {
  const coverage = [
    { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
    { area: "source:javascript", scope: "code", status: "completed", ruleIds: [], note: null },
    {
      area: "source:java",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: "2 files were larger than the size limit and were not read.",
    },
    {
      area: "history:tracked-files",
      scope: "history",
      status: "completed",
      ruleIds: [],
      note: null,
    },
    { area: "history:commits", scope: "history", status: "completed", ruleIds: [], note: null },
    { area: "web", scope: "web", status: "not_selected", ruleIds: [], note: null },
  ];
  const ruleStats = listSupportedRules()
    .slice(0, 18)
    .flatMap((rule, index) =>
      // Rules run in several areas (JavaScript and TypeScript share rules; history rules run on
      // tracked files and on commits), as in a real scan.
      (rule.scope === "history"
        ? ["history:tracked-files", "history:commits"]
        : ["source:typescript", "source:javascript"]
      ).map((area) => ({
        ruleId: rule.id,
        area,
        scope: rule.scope,
        status: "completed",
        targets: [{ unit: "files", examined: 120 + index * 3, reason: null }],
        findings: index % 4,
      })),
    );
  return {
    schemaVersion: "1.6",
    scanId: "mock-scan",
    startedAt: "2026-10-28T09:00:00.000Z",
    finishedAt: "2026-10-28T09:01:12.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code", "history"],
    overallStatus: "partial",
    target: { repo: "acme/shop", revision: "4b1e9c0", webOrigin: null },
    authorization: summary(CHECKS_ALLOWED, "allowed"),
    coverage,
    ruleStats,
    standardsCoverage: computeStandardsCoverage({ rules, coverage, ruleStats }),
    advisoryDb: { version: null, updatedAt: null },
    findings: makeFindings(findingCount),
  };
}

const RUNNING_PROGRESS = [
  { stage: "authorization", status: "started", message: "Verifying repository authorization." },
  { stage: "authorization", status: "completed", message: "Authorization verified." },
  { stage: "code", status: "started", message: "Running code analysis." },
  { stage: "code", status: "completed", message: "Finished code analysis." },
  { stage: "history", status: "started", message: "Running history analysis." },
];

function scanStatus(scopes) {
  if (scenario === "running") {
    return {
      status: "running",
      scopes,
      progress: RUNNING_PROGRESS,
      result: null,
      message: null,
      deviceCode: null,
    };
  }
  const result = makeResult(scenario === "empty" ? 0 : 240);
  if (scenario === "empty") result.findings = [];
  if (scenario === "blocked") {
    result.overallStatus = "blocked";
    result.findings = [];
    result.authorization = summary(CHECKS_BLOCKED, "blocked");
  }
  return {
    status: "done",
    scopes,
    progress: [
      ...RUNNING_PROGRESS,
      { stage: "history", status: "completed", message: "Finished history analysis." },
    ],
    result,
    message: null,
    deviceCode: null,
  };
}

const DAY_MS = 86_400_000;

/** 20 saved scans, oldest first; fixed counts so screenshots are repeatable. */
function makeTrend() {
  if (trendScenario === "trend-off") return { kind: "disabled" };
  if (trendScenario === "trend-unverified") return { kind: "unavailable", why: "not-verified" };
  const base = Date.UTC(2026, 9, 9, 9, 30);
  const total = trendScenario === "trend-few" ? 1 : 20;
  const points = [];
  for (let index = 0; index < total; index += 1) {
    const severity = {
      critical: index < 6 ? 2 : index < 12 ? 1 : 0,
      high: Math.max(2, 9 - Math.floor(index / 2) + (index % 3)),
      medium: 6 + (index % 4),
      low: 4 + (index % 3),
      info: 2,
    };
    // Scans 7 and 13 did not cover everything: their counts are lower because less was checked.
    const isPartial = index === 7 || index === 13;
    if (isPartial) {
      severity.high = 2;
      severity.medium = 2;
    }
    const sum = Object.values(severity).reduce((a, b) => a + b, 0);
    points.push({
      savedAt: base + index * DAY_MS,
      coverage: isPartial ? "partial" : "completed",
      incompleteAreas: isPartial ? 2 : 0,
      severity,
      total: sum,
      ignored: index > 4 ? 2 : 0,
      baselined: index > 9 ? 5 : 0,
      change:
        index === 0
          ? null
          : {
              new: (index * 3) % 5,
              noLongerReported: isPartial || index === 8 || index === 14 ? 0 : (index * 7) % 6,
              unchanged: 18 + (index % 5),
              notComparable: isPartial || index === 8 || index === 14 ? 9 : 0,
            },
    });
  }
  return { kind: "ready", points, skipped: 0, newerSkipped: 0, futureSkipped: 0, unread: 0 };
}

const session = {
  version: "0.1.0",
  mode: "fixed",
  project: { name: "acme-shop", repo: null },
  projectEpoch: 1,
  presetTargetPort: null,
  githubApp: { clientId: "Iv1.mock", slug: "pgard", source: "default" },
  githubAppWarning: null,
};

let lastScopes = ["code", "history"];
async function readBody(request) {
  let text = "";
  for await (const chunk of request) text += chunk;
  try {
    return JSON.parse(text || "{}");
  } catch {
    return {};
  }
}

const ROUTES = {
  // #419: the mock accepts any link; the page keeps the secret in this tab (reloads work).
  "POST /api/session/exchange": () => ({ session: "mocksessionmocksessionmocksession" }),
  "GET /api/session": () => session,
  "GET /api/target": () => null,
  "GET /api/auth": () => authStatus(),
  "POST /api/auth/verify": () => verifyStatus(),
  "POST /api/auth/owner-approval": () => ({
    status: "failed",
    reason: "Not installed yet.",
    remedy: authStatus().remedy,
  }),
  "GET /api/ports": () => ({
    services: [
      {
        port: 3000,
        url: "http://127.0.0.1:3000/",
        status: 200,
        title: "Acme Shop",
        inferredTechnologies: ["Express"],
        relatedness: { verdict: "unclear", serviceLabel: "Acme Shop", projectLabel: "shop" },
        isHttp: true,
        hasUnfollowedRedirect: false,
        error: null,
        processName: "node",
      },
    ],
    isDiscoveryAvailable: true,
    note: null,
  }),
  "GET /api/rule-texts": () => ruleTexts,
  "GET /api/trend": () => makeTrend(),
  "GET /api/scan": () => scanStatus(lastScopes),
  "POST /api/scan": (body) => {
    lastScopes = Array.isArray(body.scopes) ? body.scopes : lastScopes;
    return scanStatus(lastScopes);
  },
  "POST /api/scan/cancel": () => ({ ...scanStatus(lastScopes), status: "cancelled" }),
};

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css" };

const server = http.createServer(async (request, response) => {
  applySecurityHeaders(response);
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  if (url.pathname === "/__mock/scenario" && request.method === "POST") {
    const name = url.searchParams.get("name") ?? "";
    if (TREND_SCENARIOS.has(name)) {
      trendScenario = name;
      scenario = "results";
      response.writeHead(204).end();
      return;
    }
    if (!SCENARIOS.has(name)) {
      response.writeHead(400).end("unknown scenario");
      return;
    }
    scenario = name;
    response.writeHead(204).end();
    return;
  }
  const route = ROUTES[`${request.method} ${url.pathname}`];
  if (route !== undefined) {
    const body = request.method === "POST" ? await readBody(request) : {};
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(route(body)));
    return;
  }
  if (url.pathname.startsWith("/api/")) {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: { code: "not_found", message: "Not in the mock." } }));
    return;
  }
  const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const file = normalize(join(clientRoot, relative));
  if (!file.startsWith(clientRoot)) {
    response.writeHead(404).end();
    return;
  }
  try {
    const content = await readFile(file);
    response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
    response.end(content);
  } catch {
    response.writeHead(404).end();
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`mock dashboard on http://127.0.0.1:${port}/#token=mockmockmockmockmockmockmockmock`);
});
