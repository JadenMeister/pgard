import {
  SEVERITIES,
  type Coverage,
  type Finding,
  type ScanResult,
  type Severity,
} from "./contract.js";
import { findingIdentity } from "./compare-scans.js";
import { redactEvidence, redactFinding, redactSecrets, unmarkLocationPath } from "./redact.js";
import { isJvmSourcePath, standardsForFindings, type StandardLink } from "./rule-details.js";
import type { RuleTextCatalog } from "./rule-text.js";

/**
 * SARIF 2.1.0 output of a scan result (`pgard scan --format sarif`). A pure function: it reads the
 * result and the rule catalog and returns a plain object. PGARD does not upload it anywhere.
 *
 * Mapping (also in the README):
 * - severity -> `level`: critical, high -> `error`; medium -> `warning`; low, info -> `note`.
 * - severity -> `security-severity` (a CVSS-like 0-10 string; GitHub reads it only on the rule):
 *   critical 9.5, high 8.0, medium 5.5, low 3.0, info 1.0 (GitHub buckets: 9+ critical, 7-8.9
 *   high, 4-6.9 medium, below 4 low).
 * - Only a finding with a repository file path is emitted (GitHub rejects a result without a
 *   physical location); others (web findings) are counted in `properties.pgard.omittedFindings`
 *   and an error notification. A result has a physical location (`%SRCROOT%`-relative uri, region
 *   when it has a line). A history finding also carries its commit in `properties.pgard.commit`.
 * - `partialFingerprints["pgardFindingIdentity/v1"]` is the line-insensitive identity that
 *   baselines and scan comparison use, so a finding that only moves keeps its fingerprint.
 *   `primaryLocationLineHash` (the one GitHub uses) is `<identity>:<occurrence>`, the occurrence
 *   counted among results with the same identity in the run.
 * - A finding suppressed by `pgard.config.json` stays in the output with
 *   `suppressions: [{kind: "external", justification}]`.
 * - `baselineState` is set only when the result was compared with a baseline: `unchanged` for a
 *   finding that is in it, `new` for one that is not. A suppressed finding gets neither (it is
 *   counted under suppressions only, as in the result).
 * - `automationDetails.id` is `pgard/<requested scopes sorted, joined with +>/`: GitHub closes
 *   alerts missing from a later upload of the same category, so each scan variant is its own.
 * - Areas that are `partial` or `not_tested` become warning notifications in
 *   `invocations[0].toolExecutionNotifications`; a `blocked` or `failed` scan, or one with any `partial` or
 *   `not_tested` area, also gets an error notification and `executionSuccessful: false`. `not_selected` areas were not requested and
 *   are not reported. An empty `results` array therefore never stands for "clean" by itself.
 */

export const SARIF_SCHEMA_URL =
  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";
export const SARIF_VERSION = "2.1.0";
export const PGARD_INFORMATION_URI = "https://github.com/JadenMeister/pgard";
export const SARIF_FINGERPRINT_KEY = "pgardFindingIdentity/v1";
/** The only fingerprint GitHub code scanning uses; `<identity>:<occurrence in this run>`. */
export const SARIF_GITHUB_FINGERPRINT_KEY = "primaryLocationLineHash";
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
  // The finding path marks control and bidi characters as `\uXXXX` text; the uri carries the
  // real characters, percent-encoded, so it still points at the file.
  return unmarkLocationPath(path).split("/").map(encodeURIComponent).join("/");
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

/**
 * Only a finding with a repository file path can be in the SARIF: GitHub code scanning rejects the
 * whole upload when a result has no physical location, and PGARD does not invent file paths.
 */
export function hasSarifLocation(finding: Finding): boolean {
  const { kind, path } = finding.location;
  return kind !== "url" && path !== null && path.trim() !== "";
}

/** Findings that `buildSarif` leaves out because they have no repository file path. */
export function countSarifOmitted(result: ScanResult): number {
  return result.findings.filter((f) => !hasSarifLocation(f)).length;
}

/** True when the scan did not analyze anything: a SARIF of it must not be uploaded. */
export function sarifScanDidNotRun(result: ScanResult): boolean {
  return (
    (result.overallStatus !== "completed" && result.overallStatus !== "partial") ||
    !result.coverage.some((c) => c.status === "completed" || c.status === "partial")
  );
}

/**
 * True when some requested area did not complete (or the scan is not `completed`): the SARIF
 * lacks results for it, and uploading it would close that area's existing alerts.
 */
export function sarifScanIncomplete(result: ScanResult): boolean {
  return (
    result.overallStatus !== "completed" ||
    result.coverage.some((c) => c.status === "partial" || c.status === "not_tested")
  );
}

function buildLocations(finding: Finding): Array<Record<string, unknown>> {
  const { location } = finding;
  const physical: Record<string, unknown> = {
    artifactLocation: { uri: pathToUri(location.path ?? ""), uriBaseId: SARIF_SRCROOT },
  };
  if (location.line !== null && location.line >= 1) {
    physical.region = { startLine: location.line, endLine: location.line };
  }
  return [{ physicalLocation: physical }];
}

function buildResult(
  finding: Finding,
  ruleIndex: number,
  hasBaseline: boolean,
  occurrence: number,
): Record<string, unknown> {
  const identity = findingIdentity(finding);
  const pgard: Record<string, unknown> = {
    findingId: finding.id,
    category: finding.category,
    status: finding.status,
    confidence: finding.confidence,
    sources: [...finding.sources],
  };
  // Direct CERT Java rules: present on Java and Kotlin findings only.
  if (finding.references.cert !== undefined && finding.references.cert.length > 0) {
    pgard.certJava = [...finding.references.cert];
  }
  if (finding.context !== undefined) pgard.context = finding.context;
  if (finding.location.commit !== null) pgard.commit = finding.location.commit;
  if (finding.location.url !== null) pgard.url = finding.location.url;
  const result: Record<string, unknown> = {
    ruleId: finding.ruleId,
    ruleIndex,
    level: SARIF_LEVEL_BY_SEVERITY[finding.severity],
    message: { text: messageText(finding) },
    locations: buildLocations(finding),
    partialFingerprints: {
      [SARIF_FINGERPRINT_KEY]: identity,
      [SARIF_GITHUB_FINGERPRINT_KEY]: `${identity}:${occurrence}`,
    },
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

function certMark(link: StandardLink): string {
  if (link.viaCwe !== undefined) return ` (indirect, via ${link.viaCwe})`;
  return link.direct === true ? " (direct, Java and Kotlin files only)" : "";
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
  const rationale = details?.rationale.en ?? sample?.impact ?? title;
  const remediation = details?.remediation.en ?? sample?.recommendation ?? title;
  const links = standardsForFindings(details?.standards ?? [], findings);
  const hasJvmFinding = findings.some((f) => isJvmSourcePath(f.location.path));
  const noDirectCert =
    details?.noDirectCert !== undefined && hasJvmFinding ? details.noDirectCert.en : undefined;
  const tags = ["security"];
  for (const link of links) {
    if (link.kind === "cwe") {
      tags.push(link.id, `external/cwe/${link.id.toLowerCase()}`);
    } else if (link.kind === "owasp") {
      tags.push(`OWASP-${link.id}`);
    } else if (
      link.direct === true &&
      findings.every((f) => f.references.cert?.includes(link.id))
    ) {
      // A rule-level tag applies to every alert of the rule, so it needs every result to have it.
      tags.push(`CERT-Java-${link.id}`);
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
      ...links.map(
        (l) => `- [${l.id}${l.title === null ? "" : ` ${l.title}`}](${l.url})${certMark(l)}`,
      ),
      ...(noDirectCert === undefined ? [] : [`- SEI CERT Java: no direct rule. ${noDirectCert}`]),
    ].join("\n\n"),
  };
  if (strongest !== null) {
    rule.defaultConfiguration = { level: SARIF_LEVEL_BY_SEVERITY[strongest] };
  }
  const properties: Record<string, unknown> = { tags: [...new Set(tags)] };
  if (strongest !== null) properties["security-severity"] = SARIF_SECURITY_SEVERITY[strongest];
  rule.properties = properties;
  return rule;
}

function coverageNotifications(coverage: readonly Coverage[]): Array<Record<string, unknown>> {
  const notifications: Array<Record<string, unknown>> = [];
  for (const area of coverage) {
    if (area.status !== "partial" && area.status !== "not_tested") continue;
    const state = area.status === "partial" ? "only partly ran" : "did not run";
    const note =
      area.note === null
        ? ""
        : `: ${redactEvidence(area.note, { maxLength: MAX_NOTE }).replace(/[.\s]+$/, "")}`;
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
  const redacted = result.findings.map((f) => redactFinding(f));
  const findings = redacted.filter(hasSarifLocation);
  const omitted = redacted.filter((f) => !hasSarifLocation(f));
  const byRule = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = byRule.get(finding.ruleId) ?? [];
    list.push(finding);
    byRule.set(finding.ruleId, list);
  }
  const ruleIds = new Set<string>(byRule.keys());
  for (const finding of omitted) ruleIds.add(finding.ruleId);
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
  const executionSuccessful = !sarifScanIncomplete(result);
  if (!executionSuccessful) {
    const what =
      result.overallStatus === "blocked"
        ? "was blocked by the authorization gate"
        : result.overallStatus === "failed"
          ? "failed"
          : sarifScanDidNotRun(result)
            ? "analyzed none of the requested areas"
            : "did not complete some requested areas";
    notifications.push({
      level: "error",
      descriptor: { id: `pgard/scan/${result.overallStatus}` },
      message: {
        text: `The scan ${what}. This result is not a clean scan; do not upload this file to code scanning, it would close existing alerts for areas that did not complete.`,
      },
    });
  }
  const omittedByRule: Record<string, number> = {};
  for (const finding of omitted) {
    omittedByRule[finding.ruleId] = (omittedByRule[finding.ruleId] ?? 0) + 1;
  }
  if (omitted.length > 0) {
    const list = Object.entries(omittedByRule)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([id, count]) => `${id}: ${count}`)
      .join(", ");
    notifications.push({
      level: "error",
      descriptor: { id: "pgard/findings-omitted" },
      message: {
        text: `${omitted.length} finding(s) are not in this SARIF because they have no file location (${list}). See the text or JSON output or a report.`,
      },
    });
  }
  const occurrences = new Map<string, number>();

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
    automationDetails: { id: `pgard/${[...result.requestedScopes].sort().join("+")}/` },
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
    results: findings.map((f) => {
      const next = (occurrences.get(findingIdentity(f)) ?? 0) + 1;
      occurrences.set(findingIdentity(f), next);
      return buildResult(f, indexOf.get(f.ruleId) ?? 0, hasBaseline, next);
    }),
    properties: {
      pgard: {
        scanId: result.scanId,
        overallStatus: result.overallStatus,
        requestedScopes: [...result.requestedScopes],
        resultSchemaVersion: result.schemaVersion,
        omittedFindings: { total: omitted.length, byRule: omittedByRule },
        ...(result.incremental === undefined
          ? {}
          : {
              incremental: {
                used: result.incremental.used,
                reason: result.incremental.reason,
                basedOnScanId: result.incremental.basedOn?.scanId ?? null,
                filesRescanned: result.incremental.filesRescanned,
                filesReused: result.incremental.filesReused,
                commitsScanned: result.incremental.commitsScanned,
                commitsReused: result.incremental.commitsReused,
              },
            }),
        ...(result.target.revision === null ? {} : { revision: result.target.revision }),
        ...(repository === "" ? {} : { repository }),
      },
    },
  };
  return { $schema: SARIF_SCHEMA_URL, version: SARIF_VERSION, runs: [run] };
}
