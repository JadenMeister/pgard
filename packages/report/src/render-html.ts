import {
  SEVERITIES,
  configTestGroupNote,
  projectConfigNotices,
  type Coverage,
  type Finding,
  type RuleLocale,
  type ScanResult,
} from "@pgard/findings";
import { escapeHtml } from "./escape-html.js";
import {
  countFindingsBySeverity,
  ANALYSIS_BASIS_NOTE,
  formatFindingSummary,
  formatLocation,
  formatNoFindings,
  formatSuppressionReason,
  reportSuppressionNotices,
  BASELINE_FINDINGS_NOTE,
  BASELINE_FINDINGS_TITLE,
  SUPPRESSED_FINDINGS_NOTE,
  SUPPRESSED_FINDINGS_TITLE,
  groupReportFindings,
  labelCoverageStatus,
  labelOverallStatus,
  labelSeverity,
  FINDING_LABELS,
  prepareLocalizedReportResult,
  REPORT_DISCLAIMER,
  severityColor,
  TEST_FINDINGS_NOTE,
  TEST_FINDINGS_TITLE,
  VENDORED_FINDINGS_DETAIL,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
  type ReportLanguageOptions,
  type SeverityCounts,
} from "./format.js";

const BAR_CHART_WIDTH = 520;
const BAR_ROW_HEIGHT = 28;
const BAR_LABEL_WIDTH = 80;
const BAR_VALUE_WIDTH = 40;

/** Horizontal bar chart of findings per severity as inline SVG (no scripts, no external assets). */
export function renderSeverityBarChartSvg(counts: SeverityCounts): string {
  const maxCount = Math.max(1, ...Object.values(counts));
  const barSpace = BAR_CHART_WIDTH - BAR_LABEL_WIDTH - BAR_VALUE_WIDTH;
  const height = SEVERITIES.length * BAR_ROW_HEIGHT;
  const rows = SEVERITIES.map((severity, index) => {
    const y = index * BAR_ROW_HEIGHT;
    const width = Math.round((counts[severity] / maxCount) * barSpace);
    return [
      `<text x="0" y="${y + 18}" class="bar-label">${escapeHtml(labelSeverity(severity))}</text>`,
      `<rect x="${BAR_LABEL_WIDTH}" y="${y + 6}" width="${width}" height="16" rx="2" fill="${severityColor(severity)}"></rect>`,
      `<text x="${BAR_LABEL_WIDTH + width + 6}" y="${y + 18}" class="bar-value">${counts[severity]}</text>`,
    ].join("");
  }).join("");
  const summary = SEVERITIES.map(
    (severity) => `${labelSeverity(severity)} ${counts[severity]}`,
  ).join(", ");
  return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Findings by severity: ${escapeHtml(summary)}" width="${BAR_CHART_WIDTH}" height="${height}" viewBox="0 0 ${BAR_CHART_WIDTH} ${height}">${rows}</svg>`;
}

function renderConfigNotices(coverage: readonly Coverage[]): string {
  return projectConfigNotices(coverage)
    .filter((notice) => notice.tone === "warning")
    .map(
      (notice) =>
        `<div class="status-banner status-partial"><strong>Note:</strong> ${escapeHtml(notice.text)}</div>`,
    )
    .join("\n");
}

function renderSuppressionNotices(result: ScanResult): string {
  return reportSuppressionNotices(result)
    .map(
      (text) =>
        `<div class="status-banner status-partial"><strong>Note:</strong> ${escapeHtml(text)}</div>`,
    )
    .join("\n");
}

function renderCoverageRows(coverage: readonly Coverage[]): string {
  if (coverage.length === 0) {
    return `<tr><td colspan="4">No coverage was recorded.</td></tr>`;
  }
  return coverage
    .map(
      (entry) => `<tr class="coverage-${escapeHtml(entry.status)}">
  <td>${escapeHtml(entry.area)}</td>
  <td>${escapeHtml(entry.scope)}</td>
  <td><span class="pill pill-${escapeHtml(entry.status)}">${escapeHtml(labelCoverageStatus(entry.status))}</span></td>
  <td>${escapeHtml(entry.note ?? "")}</td>
</tr>`,
    )
    .join("\n");
}

function renderReferences(finding: Finding): string {
  const parts = [...finding.references.cwe, ...finding.references.owasp, ...finding.references.cve];
  return parts.length === 0
    ? ""
    : `<p class="refs">References: ${escapeHtml(parts.join(", "))}</p>`;
}

function renderFinding(finding: Finding, lang: RuleLocale, isNew = false): string {
  const labels = FINDING_LABELS[lang];
  const reason =
    finding.suppression === undefined
      ? ""
      : `\n  <p class="suppression"><strong>${escapeHtml(formatSuppressionReason(finding))}</strong></p>`;
  return `<article class="finding sev-${escapeHtml(finding.severity)}">
  <header>${isNew ? '\n    <span class="new-badge">NEW</span>' : ""}
    <span class="sev" style="background:${severityColor(finding.severity)}">${escapeHtml(labelSeverity(finding.severity))}</span>
    <span class="status">${escapeHtml(finding.status)}</span>
    <span class="confidence">confidence: ${escapeHtml(finding.confidence)}</span>
    <h3>${escapeHtml(finding.title)}</h3>
  </header>
  ${reason}<p class="location"><code>${escapeHtml(formatLocation(finding.location))}</code> &middot; ${escapeHtml(finding.ruleId)} &middot; ${escapeHtml(finding.category)} &middot; source: ${escapeHtml(finding.sources.join(", "))}</p>
  <dl>
    <dt>Evidence (redacted)</dt><dd><pre>${escapeHtml(finding.evidence)}</pre></dd>
    <dt>${labels.impact}</dt><dd>${escapeHtml(finding.impact)}</dd>
    <dt>${labels.recommendation}</dt><dd>${escapeHtml(finding.recommendation)}</dd>
  </dl>
  ${renderReferences(finding)}
</article>`;
}

function renderAuthorization(result: ScanResult): string {
  const rows = result.authorization.checks
    .map(
      (check) =>
        `<tr><td>${escapeHtml(check.id)}</td><td>${escapeHtml(check.status)}</td><td>${escapeHtml(check.reason)}</td></tr>`,
    )
    .join("\n");
  return `<table><thead><tr><th>Check</th><th>Status</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table>`;
}

const STYLES = `
:root { color-scheme: light; --fg:#0f172a; --muted:#475569; --line:#e2e8f0; --bg:#ffffff; --panel:#f8fafc; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 16px; font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
main { max-width: 960px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 12px; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
h3 { font-size: 15px; margin: 6px 0 0; }
.meta { color: var(--muted); margin: 0; }
.status-banner { padding: 10px 14px; border-radius: 6px; background: var(--panel); border: 1px solid var(--line); margin: 16px 0; }
.status-blocked, .status-failed { border-color: #b91c1c; }
.status-partial { border-color: #b7791f; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
.pill { display: inline-block; padding: 0 8px; border-radius: 999px; font-size: 12px; background: var(--panel); border: 1px solid var(--line); }
.pill-not_tested, .pill-partial { border-color: #b7791f; }
.finding { border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; margin: 12px 0; break-inside: avoid; }
.finding header span { margin-right: 8px; font-size: 12px; }
.sev { color: #fff; padding: 1px 8px; border-radius: 4px; }
.location code { overflow-wrap: anywhere; }
dl { margin: 8px 0 0; } dt { font-weight: 600; margin-top: 6px; } dd { margin: 0; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--panel); padding: 6px 8px; border-radius: 4px; margin: 2px 0; }
.suppression { margin: 6px 0 0; }
.new-badge { background: #0f172a; color: #fff; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
details.group > summary { cursor: pointer; font-size: 18px; font-weight: 600; margin: 32px 0 12px; }
.refs { color: var(--muted); font-size: 12px; }
.bar-label, .bar-value { font: 12px system-ui, sans-serif; fill: var(--fg); }
.chart { overflow-x: auto; }
.disclaimer { color: var(--muted); font-size: 12px; margin-top: 32px; }
`;

/**
 * Renders a self-contained HTML report from a (redacted) ScanResult. Every dynamic value is
 * escaped; the page has no scripts and a CSP that forbids loading anything.
 */
export function renderHtmlReport(input: ScanResult, options: ReportLanguageOptions = {}): string {
  const lang = options.lang ?? "en";
  const result = prepareLocalizedReportResult(input, options);
  // Headline counts cover regular code; test and fixture findings get their own section, and
  // suggestions in vendored code come last.
  const { primary, test, vendored, suppressed, baseline } = groupReportFindings(result.findings);
  const hasBaseline = result.baseline !== undefined;
  const counts = countFindingsBySeverity(primary);
  const target = result.target;
  const findingsHtml =
    primary.length === 0
      ? `<p>${escapeHtml(formatNoFindings({ test: test.length, vendored: vendored.length, suppressed }, hasBaseline))} This is not a statement that the project is secure; check coverage below.</p>`
      : primary.map((finding) => renderFinding(finding, lang, hasBaseline)).join("\n");
  const testFindingsHtml =
    test.length === 0
      ? ""
      : `\n<h2>${escapeHtml(TEST_FINDINGS_TITLE)} (${test.length})</h2>\n<p class="meta">${escapeHtml(`${TEST_FINDINGS_NOTE}${configTestGroupNote(result.coverage)}`)}</p>\n${test.map((finding) => renderFinding(finding, lang)).join("\n")}\n`;
  const vendoredFindingsHtml =
    vendored.length === 0
      ? ""
      : `\n<h2>${escapeHtml(VENDORED_FINDINGS_TITLE)} (${vendored.length})</h2>\n<p>${escapeHtml(VENDORED_FINDINGS_NOTE)}</p>\n<p class="meta">${escapeHtml(VENDORED_FINDINGS_DETAIL)}</p>\n${vendored.map((finding) => renderFinding(finding, lang)).join("\n")}\n`;

  // Suppressed and baseline findings are collapsed sections, never omitted: the count is in the
  // summary line, and a section holding a critical finding is open.
  const collapsed = (title: string, note: string, members: readonly Finding[]): string =>
    members.length === 0
      ? ""
      : `\n<details class="group"${members.some((finding) => finding.severity === "critical") ? " open" : ""}>\n<summary>${escapeHtml(title)} (${members.length})</summary>\n<p class="meta">${escapeHtml(note)}</p>\n${members.map((finding) => renderFinding(finding, lang)).join("\n")}\n</details>\n`;
  const suppressedHtml = collapsed(SUPPRESSED_FINDINGS_TITLE, SUPPRESSED_FINDINGS_NOTE, suppressed);
  const baselineHtml = collapsed(BASELINE_FINDINGS_TITLE, BASELINE_FINDINGS_NOTE, baseline);

  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>PGARD Report</title>
<style>${STYLES}</style>
</head>
<body>
<main>
<h1>PGARD security report</h1>
<p class="meta">Repository: ${escapeHtml(target.repo ?? "unknown")} &middot; Revision: ${escapeHtml(target.revision ?? "unknown")}${target.webOrigin === null ? "" : ` &middot; Web target: ${escapeHtml(target.webOrigin)}`}</p>
<p class="meta">Scan ${escapeHtml(result.scanId)} &middot; ${escapeHtml(result.startedAt)} to ${escapeHtml(result.finishedAt)} &middot; ${escapeHtml(result.tool.name)} ${escapeHtml(result.tool.version)} &middot; schema ${escapeHtml(result.schemaVersion)}</p>
<p class="meta">Requested scopes: ${escapeHtml(result.requestedScopes.join(", ") || "none")}</p>
<div class="status-banner status-${escapeHtml(result.overallStatus)}"><strong>Overall status:</strong> ${escapeHtml(labelOverallStatus(result.overallStatus))}</div>

${renderConfigNotices(result.coverage)}
${renderSuppressionNotices(result)}
<h2>Summary</h2>
<p>${escapeHtml(formatFindingSummary(result.findings, result))}</p>
<div class="chart">${renderSeverityBarChartSvg(counts)}</div>

<h2>Coverage</h2>
<table>
<thead><tr><th>Area</th><th>Scope</th><th>Status</th><th>Note</th></tr></thead>
<tbody>
${renderCoverageRows(result.coverage)}
</tbody>
</table>

<h2>${hasBaseline ? "New findings (since the baseline)" : "Findings"}</h2>
${findingsHtml}
${testFindingsHtml}${vendoredFindingsHtml}${suppressedHtml}${baselineHtml}
<h2>Authorization</h2>
<p>Decision: ${escapeHtml(result.authorization.decision)}</p>
${renderAuthorization(result)}

<h2>Analysis basis</h2>
<p>${escapeHtml(ANALYSIS_BASIS_NOTE)}</p>

<p class="disclaimer">${escapeHtml(REPORT_DISCLAIMER)}</p>
</main>
</body>
</html>
`;
}
