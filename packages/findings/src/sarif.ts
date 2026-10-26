import {
  SEVERITIES,
  type Coverage,
  type Finding,
  type ScanResult,
  type Severity,
} from "./contract.js";
import { findingIdentity } from "./compare-scans.js";
import { redactEvidence, redactFinding, redactSecrets } from "./redact.js";
import type { RuleTextCatalog } from "./rule-text.js";

/**
 * SARIF 2.1.0 output of a scan result (`pgard scan --format sarif`). A pure function: it reads the
 * result and the rule catalog and returns a plain object. PGARD does not upload it anywhere.
 *
 * Mapping (also in the README):
 * - severity -> `level`: critical, high -> `error`; medium -> `warning`; low, info -> `note`.
 * - severity -> `security-severity` (GitHub code scanning reads it as a CVSS-like 0-10 string):
 *   critical 9.5, high 8.0, medium 5.5, low 3.0, info 1.0 (GitHub buckets: 9+ critical, 7-8.9
 *   high, 4-6.9 medium, below 4 low).
 * - A file finding gets a physical location (`%SRCROOT%`-relative uri, region when it has a
 *   line). A history finding also carries its commit in `properties.pgard.commit`. A web finding
 *   has no file: it gets a logical location (kind `resource`, the redacted URL as name) and the
 *   URL in `properties.pgard.url`, and no physical location.
 * - `partialFingerprints["pgardFindingIdentity/v1"]` is the line-insensitive identity that
 *   baselines and scan comparison use, so a finding that only moves keeps its fingerprint.
 * - A finding suppressed by `pgard.config.json` stays in the output with
 *   `suppressions: [{kind: "external", justification}]`.
 * - `baselineState` is set only when the result was compared with a baseline: `unchanged` for a
 *   finding that is in it, `new` for one that is not. A suppressed finding gets neither (it is
 *   counted under suppressions only, as in the result).
 * - Areas that are `partial` or `not_tested` become warning notifications in
 *   `invocations[0].toolExecutionNotifications`; a `blocked` or `failed` scan also gets an error
 *   notification and `executionSuccessful: false`. `not_selected` areas were not requested and
 *   are not reported. An empty `results` array therefore never stands for "clean" by itself.
 */

export const SARIF_SCHEMA_URL =
  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
export const SARIF_VERSION = "2.1.0";
export const PGARD_INFORMATION_URI = "https://github.com/JadenMeister/pgard";
export const SARIF_FINGERPRINT_KEY = "pgardFindingIdentity/v1";
export const SARIF_SRCROOT = "%SRCROOT%";

export type SarifLevel = "error" | "warning" | "note";

export const SARIF_LEVEL_BY_SEVERITY: Readonly<Record<Severity, SarifLevel>> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export const SARIF_SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "1.0",
};

/** A SARIF document. Kept loose on purpose: the structure is checked by the tests. */
export interface SarifLog {
  $schema: string;
  version: typeof SARIF_VERSION;
  runs: Array<Record<string, unknown>>;
}

const MAX_MESSAGE = 700;
const MAX_NOTE = 500;

function pathToUri(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

function severityRank(severity: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(severity);
}

function messageText(finding: Finding): string {
  const text =
    finding.evidence === "" || finding.evidence === finding.title
      ? finding.title
      : `${finding.title}: ${finding.evidence}`;
  return text.length > MAX_MESSAGE ? `${text.slice(0, MAX_MESSAGE - 1)}…` : text;
}

function buildLocations(finding: Finding): Array<Record<string, unknown>> {
  const { location } = finding;
  const out: Record<string, unknown> = {};
  if (location.path !== null && location.kind !== "url") {
    const physical: Record<string, unknown> = {
      artifactLocation: { uri: pathToUri(location.path), uriBaseId: SARIF_SRCROOT },
    };
    if (location.line !== null && location.line >= 1) {
      physical.region = { startLine: location.line, endLine: location.line };
    }
    out.physicalLocation = physical;
  }
  if (location.kind === "url" && location.url !== null) {
    out.logicalLocations = [{ name: location.url, kind: "resource" }];
  }
  return Object.keys(out).length === 0 ? [] : [out];
}

function buildResult(
  finding: Finding,
  ruleIndex: number,
  hasBaseline: boolean,
): Record<string, unknown> {
  const pgard: Record<string, unknown> = {
    findingId: finding.id,
    category: finding.category,
    status: finding.status,
    confidence: finding.confidence,
    sources: [...finding.sources],
  };
  if (finding.context !== undefined) pgard.context = finding.context;
  if (finding.location.commit !== null) pgard.commit = finding.location.commit;
  if (finding.location.url !== null) pgard.url = finding.location.url;
  const result: Record<string, unknown> = {
    ruleId: finding.ruleId,
    ruleIndex,
    level: SARIF_LEVEL_BY_SEVERITY[finding.severity],
    message: { text: messageText(finding) },
    locations: buildLocations(finding),
    partialFingerprints: { [SARIF_FINGERPRINT_KEY]: findingIdentity(finding) },
    properties: {
      "security-severity": SARIF_SECURITY_SEVERITY[finding.severity],
      pgard,
    },
  };
  if (finding.suppression !== undefined) {
    result.suppressions = [
      {
        kind: "external",
        justification: redactEvidence(finding.suppression.reason, { maxLength: MAX_NOTE }),
      },
    ];
  } else if (hasBaseline) {
    result.baselineState = finding.inBaseline === true ? "unchanged" : "new";
  }
  return result;
}

function buildRule(
  id: string,
  catalog: RuleTextCatalog,
  findings: readonly Finding[],
): Record<string, unknown> {
  const texts = catalog.get(id);
  const sample = findings[0];
  const title = texts?.title.en ?? sample?.title ?? id;
  const details = texts?.details;
  const strongest = findings.reduce<Severity | null>(
    (best, f) =>
      best === null || severityRank(f.severity) > severityRank(best) ? f.severity : best,
    null,
  );
  const severity = strongest;
  const rationale = details?.rationale.en ?? sample?.impact ?? title;
  const remediation = details?.remediation.en ?? sample?.recommendation ?? title;
  const links = details?.standards ?? [];
  const tags = ["security"];
  for (const link of links) {
    if (link.kind === "cwe") {
      tags.push(link.id, `external/cwe/${link.id.toLowerCase()}`);
    } else if (link.kind === "owasp") {
      tags.push(`OWASP-${link.id}`);
    }
  }
  const helpLink = links.find((l) => l.kind === "cwe") ?? links[0];
  const rule: Record<string, unknown> = {
    id,
    name: id,
    shortDescription: { text: title },
    fullDescription: { text: rationale },
  };
  if (helpLink !== undefined) rule.helpUri = helpLink.url;
  rule.help = {
    text: remediation,
    markdown: [
      remediation,
      ...links.map((l) => `- [${l.id}${l.title === null ? "" : ` ${l.title}`}](${l.url})`),
    ].join("\n\n"),
  };
  if (severity !== null) {
    rule.defaultConfiguration = { level: SARIF_LEVEL_BY_SEVERITY[severity] };
  }
  const properties: Record<string, unknown> = { tags: [...new Set(tags)] };
  if (severity !== null) properties["security-severity"] = SARIF_SECURITY_SEVERITY[severity];
  rule.properties = properties;
  return rule;
}

function coverageNotifications(coverage: readonly Coverage[]): Array<Record<string, unknown>> {
  const notifications: Array<Record<string, unknown>> = [];
  for (const area of coverage) {
    if (area.status !== "partial" && area.status !== "not_tested") continue;
    const state = area.status === "partial" ? "only partly ran" : "did not run";
    const note =
      area.note === null ? "" : `: ${redactEvidence(area.note, { maxLength: MAX_NOTE })}`;
    notifications.push({
      level: "warning",
      descriptor: { id: `pgard/coverage/${area.status}` },
      message: { text: `Area ${area.area} ${state}${note}. Results here are not a clean scan.` },
      properties: { pgard: { area: area.area, scope: area.scope, status: area.status } },
    });
  }
  return notifications;
}

/** Builds the SARIF 2.1.0 log of `result`. Findings are redacted again; nothing is mutated. */
export function buildSarif(result: ScanResult, catalog: RuleTextCatalog): SarifLog {
  const findings = result.findings.map((f) => redactFinding(f));
  const byRule = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = byRule.get(finding.ruleId) ?? [];
    list.push(finding);
    byRule.set(finding.ruleId, list);
  }
  const ruleIds = new Set<string>(byRule.keys());
  for (const stat of result.ruleStats ?? []) ruleIds.add(stat.ruleId);
  for (const area of result.coverage) {
    if (area.status === "completed" || area.status === "partial") {
      for (const id of area.ruleIds) ruleIds.add(id);
    }
  }
  const orderedIds = [...ruleIds].sort();
  const indexOf = new Map(orderedIds.map((id, index) => [id, index]));
  const hasBaseline = result.baseline !== undefined;

  const notifications = coverageNotifications(result.coverage);
  const executionSuccessful =
    result.overallStatus === "completed" || result.overallStatus === "partial";
  if (!executionSuccessful) {
    const what =
      result.overallStatus === "blocked" ? "was blocked by the authorization gate" : "failed";
    notifications.push({
      level: "error",
      descriptor: { id: `pgard/scan/${result.overallStatus}` },
      message: {
        text: `The scan ${what} and did not analyze the project. An empty result is not a clean scan.`,
      },
    });
  }

  const repository = redactSecrets(result.target.repo ?? "");
  const run: Record<string, unknown> = {
    tool: {
      driver: {
        name: "pgard",
        version: result.tool.version,
        informationUri: PGARD_INFORMATION_URI,
        rules: orderedIds.map((id) => buildRule(id, catalog, byRule.get(id) ?? [])),
      },
    },
    originalUriBaseIds: {
      [SARIF_SRCROOT]: { description: { text: "Root of the scanned Git repository." } },
    },
    invocations: [
      {
        executionSuccessful,
        startTimeUtc: result.startedAt,
        endTimeUtc: result.finishedAt,
        toolExecutionNotifications: notifications,
      },
    ],
    results: findings.map((f) => buildResult(f, indexOf.get(f.ruleId) ?? 0, hasBaseline)),
    properties: {
      pgard: {
        scanId: result.scanId,
        overallStatus: result.overallStatus,
        requestedScopes: [...result.requestedScopes],
        resultSchemaVersion: result.schemaVersion,
        ...(result.target.revision === null ? {} : { revision: result.target.revision }),
        ...(repository === "" ? {} : { repository }),
      },
    },
  };
  return { $schema: SARIF_SCHEMA_URL, version: SARIF_VERSION, runs: [run] };
}
