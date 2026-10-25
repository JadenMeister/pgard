import { SEVERITIES, type Finding, type ScanResult } from "@pgard/findings";
import PDFDocument from "pdfkit";
import {
  countFindingsBySeverity,
  ANALYSIS_BASIS_NOTE,
  formatFindingSummary,
  formatLocation,
  formatOutsideContexts,
  groupReportFindings,
  labelCoverageStatus,
  labelOverallStatus,
  labelSeverity,
  prepareReportResult,
  REPORT_DISCLAIMER,
  severityColor,
  TEST_FINDINGS_NOTE,
  TEST_FINDINGS_TITLE,
  VENDORED_FINDINGS_DETAIL,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
} from "./format.js";

const MUTED = "#475569";
const PAGE_MARGIN = 50;
const BAR_MAX_WIDTH = 300;

const UNSUPPORTED_PDF_CHARACTERS = /[^\x20-\x7e\xa0-\xff\n]/g;

/**
 * The built-in PDF fonts only cover WinAnsi; anything else (and control characters) becomes "?"
 * so text renders predictably instead of producing broken glyphs.
 */
export function toPdfText(value: string): string {
  return value.replace(UNSUPPORTED_PDF_CHARACTERS, "?");
}

/** True when any text in the result would be altered by `toPdfText`. */
export function hasUnsupportedPdfCharacters(result: ScanResult): boolean {
  // JSON escapes newlines and control characters as ASCII, so only real text characters remain.
  return /[^\x20-\x7e\xa0-\xff]/.test(JSON.stringify(result));
}

export const PDF_REPLACEMENT_NOTICE =
  "Note: some characters outside the Latin-1 range (for example Korean text) were replaced " +
  'with "?" in this PDF. See the HTML report for the full text.';

function heading(doc: PDFKit.PDFDocument, text: string): void {
  doc.moveDown(0.8).font("Helvetica-Bold").fontSize(14).fillColor("#0f172a").text(toPdfText(text));
  doc.moveDown(0.3).font("Helvetica").fontSize(10);
}

function line(doc: PDFKit.PDFDocument, text: string, color = "#0f172a"): void {
  doc.font("Helvetica").fontSize(10).fillColor(color).text(toPdfText(text));
}

function drawSeverityBars(doc: PDFKit.PDFDocument, findings: readonly Finding[]): void {
  const counts = countFindingsBySeverity(findings);
  const maxCount = Math.max(1, ...Object.values(counts));
  for (const severity of SEVERITIES) {
    const y = doc.y;
    const width = Math.max(1, Math.round((counts[severity] / maxCount) * BAR_MAX_WIDTH));
    doc
      .font("Helvetica")
      .fontSize(10)
      .fillColor("#0f172a")
      .text(labelSeverity(severity), PAGE_MARGIN, y);
    if (counts[severity] > 0) {
      doc.rect(PAGE_MARGIN + 70, y, width, 10).fill(severityColor(severity));
    }
    doc
      .fillColor("#0f172a")
      .text(String(counts[severity]), PAGE_MARGIN + 70 + (counts[severity] > 0 ? width : 0) + 6, y);
    doc.x = PAGE_MARGIN;
    doc.y = y + 16;
  }
}

function writeFinding(doc: PDFKit.PDFDocument, finding: Finding): void {
  doc.moveDown(0.6);
  doc
    .font("Helvetica-Bold")
    .fontSize(11)
    .fillColor(severityColor(finding.severity))
    .text(`[${labelSeverity(finding.severity)}] `, { continued: true })
    .fillColor("#0f172a")
    .text(toPdfText(finding.title));
  line(
    doc,
    `${finding.status}, confidence ${finding.confidence} - ${finding.ruleId} - ${finding.category} - source: ${finding.sources.join(", ")}`,
    MUTED,
  );
  line(doc, `Location: ${formatLocation(finding.location)}`);
  line(doc, `Evidence (redacted): ${finding.evidence}`);
  line(doc, `Impact: ${finding.impact}`);
  line(doc, `Recommendation: ${finding.recommendation}`);
  const references = [
    ...finding.references.cwe,
    ...finding.references.owasp,
    ...finding.references.cve,
  ];
  if (references.length > 0) line(doc, `References: ${references.join(", ")}`, MUTED);
}

/** Renders the same content as the HTML report into a PDF buffer (pure JS, no browser). */
export function renderPdfReport(
  input: ScanResult,
  /** `compress: false` keeps the content streams readable, so tests can extract the text. */
  options: { compress?: boolean } = {},
): Promise<Buffer> {
  const result = prepareReportResult(input);
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      compress: options.compress ?? true,
      margin: PAGE_MARGIN,
      info: { Title: "PGARD Report", Creator: "pgard", Producer: "pgard" },
    });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const target = result.target;
    doc.font("Helvetica-Bold").fontSize(20).fillColor("#0f172a").text("PGARD security report");
    line(
      doc,
      `Repository: ${target.repo ?? "unknown"} - Revision: ${target.revision ?? "unknown"}`,
      MUTED,
    );
    if (target.webOrigin !== null) line(doc, `Web target: ${target.webOrigin}`, MUTED);
    line(
      doc,
      `Scan ${result.scanId} - ${result.startedAt} to ${result.finishedAt} - ${result.tool.name} ${result.tool.version} - schema ${result.schemaVersion}`,
      MUTED,
    );
    line(doc, `Requested scopes: ${result.requestedScopes.join(", ") || "none"}`, MUTED);
    if (hasUnsupportedPdfCharacters(result)) {
      doc.moveDown(0.3);
      line(doc, PDF_REPLACEMENT_NOTICE, "#b45309");
    }
    doc.moveDown(0.5);
    doc
      .font("Helvetica-Bold")
      .fontSize(11)
      .fillColor("#0f172a")
      .text(`Overall status: ${toPdfText(labelOverallStatus(result.overallStatus))}`);

    // Headline counts cover regular code; test and fixture findings get their own section, and
    // suggestions in vendored code come last.
    const { primary, test, vendored } = groupReportFindings(result.findings);
    heading(doc, "Summary");
    line(doc, formatFindingSummary(result.findings));
    doc.moveDown(0.5);
    drawSeverityBars(doc, primary);

    heading(doc, "Coverage");
    if (result.coverage.length === 0) line(doc, "No coverage was recorded.");
    for (const entry of result.coverage) {
      line(
        doc,
        `${entry.area} (${entry.scope}): ${labelCoverageStatus(entry.status)}${entry.note === null ? "" : ` - ${entry.note}`}`,
      );
    }

    heading(doc, "Findings");
    if (primary.length === 0) {
      line(
        doc,
        `No findings${formatOutsideContexts({ test: test.length, vendored: vendored.length })} in the areas that ran. This is not a statement that the project is secure; check coverage above.`,
      );
    }
    for (const finding of primary) writeFinding(doc, finding);
    if (test.length > 0) {
      heading(doc, `${TEST_FINDINGS_TITLE} (${test.length})`);
      line(doc, TEST_FINDINGS_NOTE, MUTED);
      for (const finding of test) writeFinding(doc, finding);
    }
    if (vendored.length > 0) {
      heading(doc, `${VENDORED_FINDINGS_TITLE} (${vendored.length})`);
      line(doc, VENDORED_FINDINGS_NOTE);
      line(doc, VENDORED_FINDINGS_DETAIL, MUTED);
      for (const finding of vendored) writeFinding(doc, finding);
    }

    heading(doc, "Authorization");
    line(doc, `Decision: ${result.authorization.decision}`);
    for (const check of result.authorization.checks) {
      line(doc, `${check.id}: ${check.status} - ${check.reason}`);
    }

    heading(doc, "Analysis basis");
    line(doc, ANALYSIS_BASIS_NOTE);

    doc.moveDown(1);
    doc.font("Helvetica").fontSize(8).fillColor(MUTED).text(toPdfText(REPORT_DISCLAIMER));
    doc.end();
  });
}
