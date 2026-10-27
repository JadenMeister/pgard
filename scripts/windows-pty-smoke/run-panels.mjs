// TEST-ONLY entry for the Windows ConPTY smoke test (.github/workflows/windows-tty-smoke.yml).
// It is not part of the published package (scripts/ is not packed) and is not used by the CLI.
//
// It runs the built CLI's real `pgard scan --panels` command (argument parsing, the scan command,
// the panel flow, the key reader, the cancel controller) on the real process streams, with the
// same dependency injection the flow tests use: the Git root, the project check and the scan
// itself return fixtures. Nothing here changes a policy gate in the CLI; it only supplies the
// answers the gates would have produced. No GitHub sign-in, no network, no result store.
//
// Usage: node run-panels.mjs [--status completed|partial]   (default: completed -> exit code 0)
import { SCHEMA_VERSION } from "@pgard/findings";
import { createDefaultDeps, main } from "../../apps/cli/dist/app.js";

const statusIndex = process.argv.indexOf("--status");
const overallStatus = statusIndex > 0 ? process.argv[statusIndex + 1] : "completed";

// Hostile strings that must never reach the terminal as control characters.
const HOSTILE = {
  title: "Leak \u001b[31mRED\u001b]0;PWNED-TITLE\u0007 \u009b31m C1 ‮REVERSED",
  path: "src/\u001b]8;;http://evil.example/\u0007link\u001b]8;;\u0007/‮gnp.js",
};

const finding = (n, severity, overrides = {}) => ({
  id: `f${n}`,
  ruleId: `PG-FIX-${String(n).padStart(3, "0")}`,
  title: `Fixture finding ${n}`,
  category: "injection",
  severity,
  status: "suspected",
  confidence: "medium",
  location: {
    kind: "file",
    path: `src/module${n}/handler.ts`,
    line: 10 + n,
    url: null,
    commit: null,
  },
  evidence: "req.query -> concat -> query()",
  impact: "Query structure may change",
  recommendation: "Use parameters",
  references: { cwe: [], owasp: [n % 2 === 0 ? "A05:2025" : "A01:2025"], cve: [] },
  sources: ["code"],
  ...overrides,
});

const findings = [
  finding(1, "critical", {
    title: HOSTILE.title,
    location: { kind: "file", path: HOSTILE.path, line: 7, url: null, commit: null },
  }),
  finding(2, "high", { title: "비밀번호가 코드에 그대로 들어 있습니다" }),
  finding(3, "high", {
    title: "한국어 제목이 아주 길어서 좁은 화면에서는 잘려야 하는 취약점 설명입니다",
  }),
  finding(4, "medium"),
  finding(5, "medium", {
    sources: ["code", "web"],
    location: {
      kind: "url",
      path: null,
      line: null,
      url: "http://127.0.0.1:3000/admin",
      commit: null,
    },
  }),
  finding(6, "low", { status: "informational" }),
  finding(7, "high"),
  finding(8, "medium"),
  finding(9, "low"),
  finding(10, "info", { status: "informational" }),
];

const allowed = {
  decision: "allowed",
  checks: ["repository", "github_identity", "owner_approval", "current_access", "contribution"].map(
    (id) => ({ id, status: "passed", reason: "fixture" }),
  ),
};

const result = {
  schemaVersion: SCHEMA_VERSION,
  scanId: "scan-smoke0001",
  startedAt: "2026-10-24T00:00:00.000Z",
  finishedAt: "2026-10-24T00:00:05.000Z",
  tool: { name: "pgard", version: "0.1.0" },
  requestedScopes: ["code", "history"],
  overallStatus,
  target: { repo: "owner/name", revision: "abcdef1234567890", webOrigin: null },
  authorization: allowed,
  coverage: [
    { area: "source:typescript", scope: "code", status: "completed", ruleIds: [], note: null },
    { area: "history:secrets", scope: "history", status: "completed", ruleIds: [], note: null },
  ],
  findings,
  advisoryDb: { version: null, updatedAt: null },
};

const deps = {
  ...createDefaultDeps(),
  findGitRoot: async () => process.cwd(),
  verifyProject: async () => ({
    summary: allowed,
    repo: "owner/name",
    revision: "abcdef1234567890",
  }),
  runScan: async () => result,
  // No result store: nothing is written anywhere.
  openResultStore: () => null,
};

const code = await main(
  ["scan", "--panels"],
  {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
    cwd: process.cwd(),
  },
  { deps },
);
process.exitCode = code;
