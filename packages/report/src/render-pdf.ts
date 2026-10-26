import {
  SEVERITIES,
  configTestGroupNote,
  projectConfigNotices,
  type Finding,
  type RuleLocale,
  type ScanResult,
} from "@pgard/findings";
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
} from "./format.js";
import { hasStringOutsideFont, loadPdfFonts, toFontText } from "./pdf-font.js";

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

export const PDF_FONT_REPLACEMENT_NOTICE =
  'Note: some characters this PDF font cannot show (for example emoji or other scripts) were replaced with "?". ' +
  "See the HTML report for the full text.";

/** Which font and text sanitizer one PDF render uses. */
interface PdfStyle {
  regular: string;
  bold: string;
  text: (value: string) => string;
}

const LATIN_STYLE: PdfStyle = { regular: "Helvetica", bold: "Helvetica-Bold", text: toPdfText };
const FONT_STYLE: PdfStyle = { regular: "PgardSans", bold: "PgardSans-Bold", text: toFontText };

function fontFallbackMessage(reason: string): string {
  return `The Korean-capable PDF font could not be loaded (${reason}); this PDF uses a built-in Latin-1 font.`;
}

function heading(doc: PDFKit.PDFDocument, style: PdfStyle, text: string): void {
  doc.moveDown(0.8).font(style.bold).fontSize(14).fillColor("#0f172a").text(style.text(text));
  doc.moveDown(0.3).font(style.regular).fontSize(10);
}

function line(doc: PDFKit.PDFDocument, style: PdfStyle, text: string, color = "#0f172a"): void {
  doc.font(style.regular).fontSize(10).fillColor(color).text(style.text(text));
}

function drawSeverityBars(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  findings: readonly Finding[],
): void {
  const counts = countFindingsBySeverity(findings);
  const maxCount = Math.max(1, ...Object.values(counts));
  for (const severity of SEVERITIES) {
    const y = doc.y;
    const width = Math.max(1, Math.round((counts[severity] / maxCount) * BAR_MAX_WIDTH));
    doc
      .font(style.regular)
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

function writeFinding(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  finding: Finding,
  lang: RuleLocale,
): void {
  const labels = FINDING_LABELS[lang];
  doc.moveDown(0.6);
  doc
    .font(style.bold)
    .fontSize(11)
    .fillColor(severityColor(finding.severity))
    .text(`[${labelSeverity(finding.severity)}] `, { continued: true })
    .fillColor("#0f172a")
    .text(style.text(finding.title));
  line(
    doc,
    style,
    `${finding.status}, confidence ${finding.confidence} - ${finding.ruleId} - ${finding.category} - source: ${finding.sources.join(", ")}`,
    MUTED,
  );
  line(doc, style, `Location: ${formatLocation(finding.location)}`);
  line(doc, style, `Evidence (redacted): ${finding.evidence}`);
  line(doc, style, `${labels.impact}: ${finding.impact}`);
  line(doc, style, `${labels.recommendation}: ${finding.recommendation}`);
  const references = [
    ...finding.references.cwe,
    ...finding.references.owasp,
    ...finding.references.cve,
  ];
  if (references.length > 0) line(doc, style, `References: ${references.join(", ")}`, MUTED);
}

/** Renders the same content as the HTML report into a PDF buffer (pure JS, no browser). */
export function renderPdfReport(
  input: ScanResult,
  /** `compress: false` keeps the content streams readable, so tests can extract the text. */
  options: ReportLanguageOptions & {
    compress?: boolean;
    /** Called once per render: null when the Korean-capable font is used, else why it is not. */
    onFontFallback?: (message: string | null) => void;
  } = {},
): Promise<Buffer> {
  const lang = options.lang ?? "en";
  const result = prepareLocalizedReportResult(input, options);
  const loaded = loadPdfFonts();
  const style = loaded.ok ? FONT_STYLE : LATIN_STYLE;
  options.onFontFallback?.(loaded.ok ? null : fontFallbackMessage(loaded.reason));
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      compress: options.compress ?? true,
      margin: PAGE_MARGIN,
      info: {
        Title: "PGARD Report",
        Creator: "pgard",
        Producer: "pgard",
        Subject: loaded.ok
          ? "Font: Noto Sans KR (subset, SIL OFL 1.1)"
          : fontFallbackMessage(loaded.reason),
      },
    });
    if (loaded.ok) {
      doc.registerFont(FONT_STYLE.regular, loaded.fonts.regular);
      doc.registerFont(FONT_STYLE.bold, loaded.fonts.bold);
    }
    const chunks: Buffer[] = [];
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const target = result.target;
    doc.font(style.bold).fontSize(20).fillColor("#0f172a").text("PGARD security report");
    line(
      doc,
      style,
      `Repository: ${target.repo ?? "unknown"} - Revision: ${target.revision ?? "unknown"}`,
      MUTED,
    );
    if (target.webOrigin !== null) line(doc, style, `Web target: ${target.webOrigin}`, MUTED);
    line(
      doc,
      style,
      `Scan ${result.scanId} - ${result.startedAt} to ${result.finishedAt} - ${result.tool.name} ${result.tool.version} - schema ${result.schemaVersion}`,
      MUTED,
    );
    line(doc, style, `Requested scopes: ${result.requestedScopes.join(", ") || "none"}`, MUTED);
    if (!loaded.ok) {
      doc.moveDown(0.3);
      line(doc, style, fontFallbackMessage(loaded.reason), "#b45309");
    }
    const hasReplacedText = loaded.ok
      ? hasStringOutsideFont(result)
      : hasUnsupportedPdfCharacters(result);
    if (hasReplacedText) {
      doc.moveDown(0.3);
      line(doc, style, loaded.ok ? PDF_FONT_REPLACEMENT_NOTICE : PDF_REPLACEMENT_NOTICE, "#b45309");
    }
    doc.moveDown(0.5);
    doc
      .font(style.bold)
      .fontSize(11)
      .fillColor("#0f172a")
      .text(`Overall status: ${style.text(labelOverallStatus(result.overallStatus))}`);

    // Headline counts cover regular code; test and fixture findings get their own section, and
    // suggestions in vendored code come last.
    const { primary, test, vendored } = groupReportFindings(result.findings);
    for (const notice of projectConfigNotices(result.coverage)) {
      if (notice.tone !== "warning") continue;
      doc.moveDown(0.3);
      line(doc, style, `Note: ${notice.text}`, "#b45309");
    }
    heading(doc, style, "Summary");
    line(doc, style, formatFindingSummary(result.findings));
    doc.moveDown(0.5);
    drawSeverityBars(doc, style, primary);

    heading(doc, style, "Coverage");
    if (result.coverage.length === 0) line(doc, style, "No coverage was recorded.");
    for (const entry of result.coverage) {
      line(
        doc,
        style,
        `${entry.area} (${entry.scope}): ${labelCoverageStatus(entry.status)}${entry.note === null ? "" : ` - ${entry.note}`}`,
      );
    }

    heading(doc, style, "Findings");
    if (primary.length === 0) {
      line(
        doc,
        style,
        `No findings${formatOutsideContexts({ test: test.length, vendored: vendored.length })} in the areas that ran. This is not a statement that the project is secure; check coverage above.`,
      );
    }
    for (const finding of primary) writeFinding(doc, style, finding, lang);
    if (test.length > 0) {
      heading(doc, style, `${TEST_FINDINGS_TITLE} (${test.length})`);
      line(doc, style, `${TEST_FINDINGS_NOTE}${configTestGroupNote(result.coverage)}`, MUTED);
      for (const finding of test) writeFinding(doc, style, finding, lang);
    }
    if (vendored.length > 0) {
      heading(doc, style, `${VENDORED_FINDINGS_TITLE} (${vendored.length})`);
      line(doc, style, VENDORED_FINDINGS_NOTE);
      line(doc, style, VENDORED_FINDINGS_DETAIL, MUTED);
      for (const finding of vendored) writeFinding(doc, style, finding, lang);
    }

    heading(doc, style, "Authorization");
    line(doc, style, `Decision: ${result.authorization.decision}`);
    for (const check of result.authorization.checks) {
      line(doc, style, `${check.id}: ${check.status} - ${check.reason}`);
    }

    heading(doc, style, "Analysis basis");
    line(doc, style, ANALYSIS_BASIS_NOTE);

    doc.moveDown(1);
    doc.font(style.regular).fontSize(8).fillColor(MUTED).text(style.text(REPORT_DISCLAIMER));
    doc.end();
  });
}
