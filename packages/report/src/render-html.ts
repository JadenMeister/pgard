import {
  SEVERITIES,
  pickText,
  configTestGroupNote,
  projectConfigNotices,
  type Coverage,
  type Finding,
  type ScanResult,
} from "@pgard/findings";
import { escapeHtml } from "./escape-html.js";
import { codeOnlyLabel } from "./code-only-text.js";
import { incrementalLine } from "./incremental-text.js";
import {
  countFindingsBySeverity,
  FINDING_LABELS,
  formatLocation,
  groupReportFindings,
  prepareLocalizedReportResult,
  severityColor,
  type ReportLanguageOptions,
  type SeverityCounts,
} from "./format.js";
import {
  cweTop25CountsText,
  cweTop25Rows,
  findingDetails,
  standardMark,
  localizedSuppressionNotices,
  noFindingsLine,
  owaspRows,
  reportContext,
  ruleGuidance,
  ruleStatRows,
  summaryLine,
  suppressionReasonLine,
  type ReportContext,
} from "./report-view.js";
import { REPORT_TEXT, type ReportText } from "./report-text.js";

const BAR_CHART_WIDTH = 520;
const BAR_ROW_HEIGHT = 28;
const BAR_LABEL_WIDTH = 80;
const BAR_VALUE_WIDTH = 40;

/** Horizontal bar chart of findings per severity as inline SVG (no scripts, no external assets). */
export function renderSeverityBarChartSvg(
  counts: SeverityCounts,
  /** Labels and aria text in the report language; default English. */
  t: Pick<ReportText, "severity" | "svgAria"> = REPORT_TEXT.en,
): string {
  const maxCount = Math.max(1, ...Object.values(counts));
  const barSpace = BAR_CHART_WIDTH - BAR_LABEL_WIDTH - BAR_VALUE_WIDTH;
  const height = SEVERITIES.length * BAR_ROW_HEIGHT;
  const rows = SEVERITIES.map((severity, index) => {
    const y = index * BAR_ROW_HEIGHT;
    const width = Math.round((counts[severity] / maxCount) * barSpace);
    return [
      `<text x="0" y="${y + 18}" class="bar-label">${escapeHtml(t.severity[severity])}</text>`,
      `<rect x="${BAR_LABEL_WIDTH}" y="${y + 6}" width="${width}" height="16" rx="2" fill="${severityColor(severity)}"></rect>`,
      `<text x="${BAR_LABEL_WIDTH + width + 6}" y="${y + 18}" class="bar-value">${counts[severity]}</text>`,
    ].join("");
  }).join("");
  const summary = SEVERITIES.map((severity) => `${t.severity[severity]} ${counts[severity]}`).join(
    ", ",
  );
  return `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${escapeHtml(t.svgAria(summary))}" width="${BAR_CHART_WIDTH}" height="${height}" viewBox="0 0 ${BAR_CHART_WIDTH} ${height}">${rows}</svg>`;
}

/** The report word for a known value; an unexpected value (hand-made JSON) is shown as stored. */
function word(words: Readonly<Record<string, string>>, value: unknown, fallback?: string): string {
  if (typeof value === "string" && Object.hasOwn(words, value)) return words[value] ?? "";
  return fallback ?? String(value);
}

function noteBanner(ctx: ReportContext, text: string): string {
  return `<div class="status-banner status-partial"><strong>${escapeHtml(ctx.t.note)}:</strong> ${escapeHtml(text)}</div>`;
}

function renderConfigNotices(coverage: readonly Coverage[], ctx: ReportContext): string {
  return projectConfigNotices(coverage)
    .filter((notice) => notice.tone === "warning")
    .map((notice) => noteBanner(ctx, notice.text))
    .join("\n");
}

function renderSuppressionNotices(result: ScanResult, ctx: ReportContext): string {
  return localizedSuppressionNotices(result, ctx)
    .map((text) => noteBanner(ctx, text))
    .join("\n");
}

function renderCoverageRows(coverage: readonly Coverage[], ctx: ReportContext): string {
  if (coverage.length === 0) {
    return `<tr><td colspan="4">${escapeHtml(ctx.t.noCoverage)}</td></tr>`;
  }
  return coverage
    .map(
      (entry) => `<tr class="coverage-${escapeHtml(entry.status)}">
  <td>${escapeHtml(entry.area)}</td>
  <td>${escapeHtml(entry.scope)}</td>
  <td><span class="pill pill-${escapeHtml(entry.status)}">${escapeHtml(word(ctx.t.coverageStatus, entry.status, ctx.t.unknownLabel))}</span></td>
  <td>${escapeHtml(entry.note ?? "")}</td>
</tr>`,
    )
    .join("\n");
}

/** An external link to an official standards page: opens a new tab without opener or referrer. */
function externalLink(url: string, text: string): string {
  return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
}

function renderReferences(finding: Finding, ctx: ReportContext): string {
  const parts = [...finding.references.cwe, ...finding.references.owasp, ...finding.references.cve];
  return parts.length === 0
    ? ""
    : `<p class="refs">${escapeHtml(ctx.t.references)}: ${escapeHtml(parts.join(", "))}</p>`;
}

function renderStandards(finding: Finding, ctx: ReportContext): string {
  const details = findingDetails(finding, ctx);
  if (details === undefined) return "";
  if (details.standards.length === 0 && details.noDirectCert === undefined) return "";
  const items = details.standards
    .map((link) => {
      const via = escapeHtml(standardMark(link, ctx.t));
      return `<li>${externalLink(link.url, link.id)}${link.title === null ? "" : ` ${escapeHtml(link.title)}`}${via}</li>`;
    })
    .join("");
  const none =
    details.noDirectCert === undefined
      ? ""
      : `<li>${escapeHtml(ctx.t.certNone)}: ${escapeHtml(pickText(details.noDirectCert, ctx.chrome))}</li>`;
  return `<div class="standards"><strong>${escapeHtml(ctx.t.standards)}</strong><ul>${items}${none}</ul></div>`;
}

interface Piece {
  html: string;
  /** The same block was already written for an earlier finding of the rule. */
  isRepeat: boolean;
}

const shownPerRender = new WeakMap<ReportContext, Set<string>>();
const anchoredPerRender = new WeakMap<ReportContext, Set<string>>();

function stateOf(map: WeakMap<ReportContext, Set<string>>, ctx: ReportContext): Set<string> {
  let state = map.get(ctx);
  if (state === undefined) {
    state = new Set();
    map.set(ctx, state);
  }
  return state;
}

/**
 * Rule-level blocks (guidance, examples) are the same for every finding of a rule, so only the
 * first one in the report is written: 100 findings of one rule would otherwise repeat them 100
 * times. The key includes the text, so a finding with its own guidance still shows it. Later
 * findings get a link to the first one (see `renderFinding`).
 */
function firstTimeOnly(ctx: ReportContext, kind: string, finding: Finding, html: string): Piece {
  if (html === "") return { html: "", isRepeat: false };
  const shown = stateOf(shownPerRender, ctx);
  const key = `${kind}\u0000${finding.ruleId}\u0000${html}`;
  if (shown.has(key)) return { html: "", isRepeat: true };
  shown.add(key);
  return { html, isRepeat: false };
}

function renderExamples(finding: Finding, ctx: ReportContext): Piece {
  const details = findingDetails(finding, ctx);
  if (details === undefined || details.examples.length === 0) return { html: "", isRepeat: false };
  const blocks = details.examples
    .map((example) => {
      const note =
        example.note === undefined
          ? ""
          : `<p class="meta">${escapeHtml(example.note[ctx.lang])}</p>`;
      return `<p><strong>${escapeHtml(ctx.t.vulnerable)}</strong> <span class="meta">${escapeHtml(example.language)}</span></p><pre class="code"><code>${escapeHtml(example.vulnerable)}</code></pre><p><strong>${escapeHtml(ctx.t.safe)}</strong></p><pre class="code"><code>${escapeHtml(example.safe)}</code></pre>${note}`;
    })
    .join("");
  return firstTimeOnly(
    ctx,
    "examples",
    finding,
    `<details class="examples"><summary>${escapeHtml(ctx.t.examples(details.examples.length))}</summary>${blocks}</details>`,
  );
}

function renderGuidance(finding: Finding, ctx: ReportContext): Piece {
  const guidance = ruleGuidance(finding, findingDetails(finding, ctx), ctx.lang);
  const rows = [
    guidance.rationale === null
      ? ""
      : `<dt>${escapeHtml(ctx.t.ruleRationale)}</dt><dd>${escapeHtml(guidance.rationale)}</dd>`,
    guidance.remediation === null
      ? ""
      : `<dt>${escapeHtml(ctx.t.ruleRemediation)}</dt><dd>${escapeHtml(guidance.remediation)}</dd>`,
  ].join("");
  return rows === ""
    ? { html: "", isRepeat: false }
    : firstTimeOnly(ctx, "guidance", finding, `<dl class="guidance">${rows}</dl>`);
}

/** Anchor id of the first finding of a rule that shows its examples and guidance. */
const ruleAnchor = (ruleId: string): string => `rule-${ruleId}`;

function renderFinding(finding: Finding, ctx: ReportContext, isNew = false): string {
  const t = ctx.t;
  const labels = FINDING_LABELS[ctx.lang];
  const reason =
    finding.suppression === undefined
      ? ""
      : `\n  <p class="suppression"><strong>${escapeHtml(suppressionReasonLine(finding, ctx))}</strong></p>`;
  const severity = word(t.severity, finding.severity, t.unknownLabel);
  const guidance = renderGuidance(finding, ctx);
  const examples = renderExamples(finding, ctx);
  const anchored = stateOf(anchoredPerRender, ctx);
  let anchor = "";
  if ((guidance.html !== "" || examples.html !== "") && !anchored.has(finding.ruleId)) {
    anchored.add(finding.ruleId);
    anchor = ` id="${escapeHtml(ruleAnchor(finding.ruleId))}"`;
  }
  const pointer =
    (guidance.isRepeat || examples.isRepeat) && anchored.has(finding.ruleId)
      ? `<p class="meta rule-details-link"><a href="#${escapeHtml(ruleAnchor(finding.ruleId))}">${escapeHtml(t.ruleDetailsAbove(finding.ruleId))}</a></p>`
      : "";
  return `<article class="finding sev-${escapeHtml(finding.severity)}"${anchor}>
  <header>${isNew ? `\n    <span class="new-badge">${escapeHtml(t.newBadge)}</span>` : ""}
    <span class="sev" style="background:${severityColor(finding.severity)}">${escapeHtml(severity)}</span>
    <span class="status">${escapeHtml(word(t.findingStatus, finding.status))}</span>
    <span class="confidence">${escapeHtml(t.confidence)}: ${escapeHtml(word(t.confidenceLevel, finding.confidence))}</span>
    <h3>${escapeHtml(finding.title)}</h3>
  </header>
  ${reason}<p class="location"><code>${escapeHtml(formatLocation(finding.location))}</code> &middot; ${escapeHtml(finding.ruleId)} &middot; ${escapeHtml(finding.category)} &middot; ${escapeHtml(t.source)}: ${escapeHtml(finding.sources.join(", "))}</p>
  <dl>
    <dt>${escapeHtml(t.evidence)}</dt><dd><pre>${escapeHtml(finding.evidence)}</pre></dd>
    <dt>${labels.impact}</dt><dd>${escapeHtml(finding.impact)}</dd>
    <dt>${labels.recommendation}</dt><dd>${escapeHtml(finding.recommendation)}</dd>
  </dl>
  ${guidance.html}${renderStandards(finding, ctx)}${examples.html}${pointer}${renderReferences(finding, ctx)}
</article>`;
}

function renderAuthorization(result: ScanResult, ctx: ReportContext): string {
  const rows = result.authorization.checks
    .map(
      (check) =>
        `<tr><td>${escapeHtml(check.id)}</td><td>${escapeHtml(check.status)}</td><td>${escapeHtml(check.reason)}</td></tr>`,
    )
    .join("\n");
  return `<table><thead><tr><th>${escapeHtml(ctx.t.check)}</th><th>${escapeHtml(ctx.t.status)}</th><th>${escapeHtml(ctx.t.reason)}</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderStandardsCoverage(result: ScanResult, ctx: ReportContext): string {
  const t = ctx.t;
  if (result.standardsCoverage === undefined) {
    return `<h2>${escapeHtml(t.standardsTitle)}</h2>\n<p class="meta">${escapeHtml(t.notRecorded)}</p>`;
  }
  const columns = t.standardColumns;
  const owasp = owaspRows(result, ctx)
    .map(
      (row) =>
        `<tr><td>${row.url === "" ? escapeHtml(row.id) : externalLink(row.url, row.id)}</td><td>${escapeHtml(row.title)}</td><td><span class="pill state-${escapeHtml(row.state)}">${escapeHtml(row.stateLabel)}</span></td><td>${escapeHtml(row.breadth)}</td><td>${escapeHtml(row.rules)}</td><td>${escapeHtml(row.reason)}</td></tr>`,
    )
    .join("\n");
  const cwe = cweTop25Rows(result, ctx)
    .map(
      (row) =>
        `<tr><td>${escapeHtml(String(row.rank ?? ""))}</td><td>${row.url === "" ? escapeHtml(row.id) : externalLink(row.url, row.id)}</td><td>${escapeHtml(row.title)}</td><td><span class="pill state-${escapeHtml(row.state)}">${escapeHtml(row.stateLabel)}</span></td><td>${escapeHtml(row.rules)}</td><td>${escapeHtml(row.reason)}</td></tr>`,
    )
    .join("\n");
  return `<h2>${escapeHtml(t.standardsTitle)}</h2>
<p class="meta standards-note">${escapeHtml(t.standardsNote)}</p>
<table class="standards-map">
<thead><tr><th>${escapeHtml(columns.id)}</th><th>${escapeHtml(columns.category)}</th><th>${escapeHtml(columns.state)}</th><th>${escapeHtml(columns.breadth)}</th><th>${escapeHtml(columns.rules)}</th><th>${escapeHtml(columns.reason)}</th></tr></thead>
<tbody>
${owasp}
</tbody>
</table>
<details class="group">
<summary>${escapeHtml(t.cweTop25Title)}: ${escapeHtml(cweTop25CountsText(result, ctx))}</summary>
<table class="standards-map">
<thead><tr><th>${escapeHtml(t.cweColumns.rank)}</th><th>${escapeHtml(t.cweColumns.id)}</th><th>${escapeHtml(t.cweColumns.name)}</th><th>${escapeHtml(columns.state)}</th><th>${escapeHtml(columns.rules)}</th><th>${escapeHtml(columns.reason)}</th></tr></thead>
<tbody>
${cwe}
</tbody>
</table>
</details>`;
}

function renderRuleStats(result: ScanResult, ctx: ReportContext): string {
  const t = ctx.t;
  if (result.ruleStats === undefined) return "";
  const columns = t.ruleStatsColumns;
  const rows = ruleStatRows(result, ctx)
    .map(
      (row) =>
        `<tr><td>${escapeHtml(row.ruleId)}${row.title === "" ? "" : `<br><span class="meta">${escapeHtml(row.title)}</span>`}</td><td>${escapeHtml(row.area)}</td><td>${escapeHtml(row.targets)}</td><td>${row.findings}</td><td>${escapeHtml(row.status)}</td></tr>`,
    )
    .join("\n");
  return `<details class="group rule-stats">
<summary>${escapeHtml(t.ruleStatsTitle(result.ruleStats.length))}</summary>
<p class="meta">${escapeHtml(t.ruleStatsNote)}</p>
<table>
<thead><tr><th>${escapeHtml(columns.rule)}</th><th>${escapeHtml(columns.area)}</th><th>${escapeHtml(columns.targets)}</th><th>${escapeHtml(columns.findings)}</th><th>${escapeHtml(columns.status)}</th></tr></thead>
<tbody>
${rows}
</tbody>
</table>
</details>`;
}

function renderLicense(result: ScanResult, ctx: ReportContext): string {
  const t = ctx.t;
  const usesStandards =
    result.standardsCoverage !== undefined ||
    result.findings.some((finding) => (findingDetails(finding, ctx)?.standards.length ?? 0) > 0);
  if (!usesStandards) return "";
  return `<h2>${escapeHtml(t.licenseTitle)}</h2>
<p class="meta">${escapeHtml(t.licenseIntro)}</p>
<ul class="meta license">
<li>${escapeHtml(t.licenseOwasp)}</li>
<li>${escapeHtml(t.licenseCwe)}</li>
<li>${escapeHtml(t.licenseCert)}</li>
</ul>`;
}

const STYLES = `
:root { color-scheme: light; --fg:#0f172a; --muted:#475569; --line:#e2e8f0; --bg:#ffffff; --panel:#f8fafc; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 16px; font: 14px/1.5 system-ui, -apple-system, "Segoe UI", "Apple SD Gothic Neo", "Malgun Gothic", "Noto Sans KR", sans-serif; color: var(--fg); background: var(--bg); }
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
.pill-not_tested, .pill-partial, .pill.state-rules_partial { border-color: #b7791f; }
.pill.state-not_run, .pill.state-no_rules { color: var(--muted); }
.finding { border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; margin: 12px 0; break-inside: avoid; }
.finding header span { margin-right: 8px; font-size: 12px; }
.sev { color: #fff; padding: 1px 8px; border-radius: 4px; }
.location code { overflow-wrap: anywhere; }
dl { margin: 8px 0 0; } dt { font-weight: 600; margin-top: 6px; } dd { margin: 0; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--panel); padding: 6px 8px; border-radius: 4px; margin: 2px 0; }
pre.code { margin: 2px 0 8px; }
.suppression { margin: 6px 0 0; }
.new-badge { background: #0f172a; color: #fff; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
details.group > summary { cursor: pointer; font-size: 18px; font-weight: 600; margin: 32px 0 12px; }
details.group table { margin-top: 8px; }
details.examples { margin: 8px 0 0; }
details.examples > summary { cursor: pointer; font-weight: 600; }
.guidance { margin: 4px 0 0; }
.standards ul { margin: 2px 0 6px; padding-left: 20px; }
.standards li { font-size: 12px; }
.standards-map { font-size: 13px; }
.refs { color: var(--muted); font-size: 12px; }
.license { font-size: 12px; }
a { color: #1d4ed8; }
.bar-label, .bar-value { font: 12px system-ui, sans-serif; fill: var(--fg); }
.chart { overflow-x: auto; }
.disclaimer { color: var(--muted); font-size: 12px; margin-top: 32px; }
.code-only-banner { position: sticky; top: 0; z-index: 1; margin: -32px -16px 16px; padding: 8px 16px; background: #fef3c7; color: #78350f; border-bottom: 1px solid #b7791f; font-weight: 600; }
.code-only { border: 2px solid #b7791f; border-radius: 6px; padding: 12px 14px; margin: 16px 0; background: #fffbeb; }
.code-only h2 { margin: 0 0 6px; border: 0; padding: 0; color: #78350f; }
.code-only p { margin: 4px 0; }
@media print {
  /* A fixed element repeats on every printed page. */
  .code-only-banner { position: fixed; top: 0; left: 0; right: 0; margin: 0; }
  body { padding-top: 48px; }
}
`;

/** The banner and cover block of a code-only result (JSON 1.7); empty for any other result. */
function renderCodeOnly(
  result: ScanResult,
  lang: ReportContext["lang"],
): {
  banner: string;
  cover: string;
} {
  const label = codeOnlyLabel(result, lang);
  if (label === null) return { banner: "", cover: "" };
  return {
    banner: `<div class="code-only-banner" role="note">${escapeHtml(label.banner)}</div>\n`,
    cover: `<section class="code-only" aria-label="${escapeHtml(label.title)}">\n<h2>${escapeHtml(label.title)}</h2>\n<p>${escapeHtml(label.body)}</p>\n<p>${escapeHtml(label.reason)}</p>\n</section>\n`,
  };
}

/** "Incremental: ..." or "Full scan: ..." under the summary; empty without the field. */
function renderIncremental(result: ScanResult, lang: ReportContext["lang"]): string {
  const line = incrementalLine(result.incremental, lang);
  return line === null
    ? ""
    : `<p class="meta"><strong>${escapeHtml(line.label)}:</strong> ${escapeHtml(line.value)}</p>`;
}

/**
 * Renders a self-contained HTML report from a (redacted) ScanResult. Every dynamic value is
 * escaped; the page has no scripts and a CSP that forbids loading anything. Standards links are
 * the only external references: plain anchors to official pages, opened without opener or referrer.
 */
export function renderHtmlReport(input: ScanResult, options: ReportLanguageOptions = {}): string {
  const ctx = reportContext(options);
  const { lang, t } = ctx;
  const result = prepareLocalizedReportResult(input, options);
  // Headline counts cover regular code; test and fixture findings get their own section, and
  // suggestions in vendored code come last.
  const { primary, test, vendored, suppressed, baseline } = groupReportFindings(result.findings);
  const hasBaseline = result.baseline !== undefined;
  const counts = countFindingsBySeverity(primary);
  const target = result.target;
  const findingsHtml =
    primary.length === 0
      ? `<p>${escapeHtml(noFindingsLine({ test: test.length, vendored: vendored.length, suppressed }, hasBaseline, ctx))} ${escapeHtml(t.noFindingsTail)}</p>`
      : primary.map((finding) => renderFinding(finding, ctx, hasBaseline)).join("\n");
  const configNote = lang === "en" ? configTestGroupNote(result.coverage) : "";
  const testFindingsHtml =
    test.length === 0
      ? ""
      : `\n<h2>${escapeHtml(t.testTitle)} (${test.length})</h2>\n<p class="meta">${escapeHtml(`${t.testNote}${configNote}`)}</p>\n${test.map((finding) => renderFinding(finding, ctx)).join("\n")}\n`;
  const vendoredFindingsHtml =
    vendored.length === 0
      ? ""
      : `\n<h2>${escapeHtml(t.vendoredTitle)} (${vendored.length})</h2>\n<p>${escapeHtml(t.vendoredNote)}</p>\n<p class="meta">${escapeHtml(t.vendoredDetail)}</p>\n${vendored.map((finding) => renderFinding(finding, ctx)).join("\n")}\n`;

  // Suppressed and baseline findings are collapsed sections, never omitted: the count is in the
  // summary line, and a section holding a critical finding is open.
  const collapsed = (title: string, note: string, members: readonly Finding[]): string =>
    members.length === 0
      ? ""
      : `\n<details class="group"${members.some((finding) => finding.severity === "critical") ? " open" : ""}>\n<summary>${escapeHtml(title)} (${members.length})</summary>\n<p class="meta">${escapeHtml(note)}</p>\n${members.map((finding) => renderFinding(finding, ctx)).join("\n")}\n</details>\n`;
  const suppressedHtml = collapsed(t.suppressedTitle, t.suppressedNote, suppressed);
  const baselineHtml = collapsed(t.baselineTitle, t.baselineNote, baseline);
  const codeOnly = renderCodeOnly(input, lang);

  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(t.htmlTitle)}</title>
<style>${STYLES}</style>
</head>
<body>
${codeOnly.banner}<main>
<h1>${escapeHtml(t.title)}</h1>
<p class="meta">${escapeHtml(t.repository)}: ${escapeHtml(target.repo ?? t.unknown)} &middot; ${escapeHtml(t.revision)}: ${escapeHtml(target.revision ?? t.unknown)}${target.webOrigin === null ? "" : ` &middot; ${escapeHtml(t.webTarget)}: ${escapeHtml(target.webOrigin)}`}</p>
<p class="meta">${escapeHtml(t.scan)} ${escapeHtml(result.scanId)} &middot; ${escapeHtml(result.startedAt)} ${escapeHtml(t.to)} ${escapeHtml(result.finishedAt)} &middot; ${escapeHtml(result.tool.name)} ${escapeHtml(result.tool.version)} &middot; ${escapeHtml(t.schema)} ${escapeHtml(result.schemaVersion)}</p>
<p class="meta">${escapeHtml(t.requestedScopes)}: ${escapeHtml(result.requestedScopes.join(", ") || t.none)}</p>
${codeOnly.cover}<div class="status-banner status-${escapeHtml(result.overallStatus)}"><strong>${escapeHtml(t.overallStatus)}:</strong> ${escapeHtml(word(t.overall, result.overallStatus, t.unknownLabel))}</div>

${renderConfigNotices(result.coverage, ctx)}
${renderSuppressionNotices(result, ctx)}
<h2>${escapeHtml(t.summary)}</h2>
<p>${escapeHtml(summaryLine(result, ctx))}</p>
${renderIncremental(result, lang)}
<div class="chart">${renderSeverityBarChartSvg(counts, t)}</div>

<h2>${escapeHtml(t.coverage)}</h2>
<table>
<thead><tr><th>${escapeHtml(t.area)}</th><th>${escapeHtml(t.scope)}</th><th>${escapeHtml(t.status)}</th><th>${escapeHtml(t.noteColumn)}</th></tr></thead>
<tbody>
${renderCoverageRows(result.coverage, ctx)}
</tbody>
</table>

${renderStandardsCoverage(result, ctx)}
${renderRuleStats(result, ctx)}

<h2>${escapeHtml(hasBaseline ? t.newFindings : t.findings)}</h2>
${findingsHtml}
${testFindingsHtml}${vendoredFindingsHtml}${suppressedHtml}${baselineHtml}
<h2>${escapeHtml(t.authorization)}</h2>
<p>${escapeHtml(t.decision)}: ${escapeHtml(result.authorization.decision)}</p>
${renderAuthorization(result, ctx)}

<h2>${escapeHtml(t.analysisBasis)}</h2>
<p>${escapeHtml(t.analysisBasisNote)}</p>

${renderLicense(result, ctx)}
<p class="disclaimer">${escapeHtml(t.disclaimer)}</p>
</main>
</body>
</html>
`;
}
