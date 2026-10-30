import {
  SEVERITIES,
  configTestGroupNote,
  projectConfigNotices,
  type Finding,
  type ScanResult,
  type StandardLink,
} from "@pgard/findings";
import PDFDocument from "pdfkit";
import {
  countFindingsBySeverity,
  FINDING_LABELS,
  formatLocation,
  groupReportFindings,
  prepareLocalizedReportResult,
  severityColor,
  type ReportLanguageOptions,
} from "./format.js";
import { hasStringOutsideFont, loadPdfFonts, toFontText } from "./pdf-font.js";
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
  rulesWithExamples,
  standardsLinksOf,
  summaryLine,
  suppressionReasonLine,
  type ReportContext,
} from "./report-view.js";
import { codeOnlyLabel } from "./code-only-text.js";
import { incrementalLine } from "./incremental-text.js";

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
export function hasUnsupportedPdfCharacters(result: unknown): boolean {
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
  return `The Korean-capable PDF font could not be loaded (${reason}); this PDF uses a built-in Latin-1 font, so a Korean report is rendered in English.`;
}

function heading(doc: PDFKit.PDFDocument, style: PdfStyle, text: string): void {
  doc.moveDown(0.8).font(style.bold).fontSize(14).fillColor("#0f172a").text(style.text(text));
  doc.moveDown(0.3).font(style.regular).fontSize(10);
}

function line(doc: PDFKit.PDFDocument, style: PdfStyle, text: string, color = "#0f172a"): void {
  doc.font(style.regular).fontSize(10).fillColor(color).text(style.text(text));
}

/** Tabs and carriage returns are not in the font: spaces keep code readable. */
function codeText(value: string): string {
  return value.replace(/\t/g, "  ").replace(/\r\n?/g, "\n");
}

/** Code block: small text, indented, no colour. The code itself is never translated. */
function codeBlock(doc: PDFKit.PDFDocument, style: PdfStyle, code: string): void {
  doc
    .font(style.regular)
    .fontSize(8.5)
    .fillColor("#0f172a")
    .text(style.text(codeText(code)), PAGE_MARGIN + 12, doc.y, {
      width: doc.page.width - 2 * PAGE_MARGIN - 12,
    });
  doc.x = PAGE_MARGIN;
}

/** "Label: id1, id2": the ids are clickable links to the official pages (full URLs: appendix C). */
function linkLine(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  label: string,
  links: readonly StandardLink[],
): void {
  doc
    .font(style.regular)
    .fontSize(10)
    .fillColor(MUTED)
    .text(style.text(`${label}: `), {
      continued: true,
    });
  links.forEach((link, index) => {
    doc
      .fillColor("#1d4ed8")
      .text(style.text(link.id), { continued: index < links.length - 1, link: link.url });
    if (index < links.length - 1) doc.fillColor(MUTED).text(", ", { continued: true });
  });
}

function drawSeverityBars(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  findings: readonly Finding[],
  ctx: ReportContext,
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
      .text(style.text(ctx.t.severity[severity]), PAGE_MARGIN, y);
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
  ctx: ReportContext,
  isNew = false,
): void {
  const t = ctx.t;
  const labels = FINDING_LABELS[ctx.chrome];
  doc.moveDown(0.6);
  if (isNew) line(doc, style, t.newSinceBaseline, "#0f172a");
  if (finding.suppression !== undefined) {
    line(doc, style, suppressionReasonLine(finding, ctx), "#b45309");
  }
  doc
    .font(style.bold)
    .fontSize(11)
    .fillColor(severityColor(finding.severity))
    .text(style.text(`[${severityWord(finding.severity, ctx)}] `), { continued: true })
    .fillColor("#0f172a")
    .text(style.text(finding.title));
  line(
    doc,
    style,
    `${word(t.findingStatus, finding.status)}, ${t.confidence} ${word(t.confidenceLevel, finding.confidence)} - ${finding.ruleId} - ${finding.category} - ${t.source}: ${finding.sources.join(", ")}`,
    MUTED,
  );
  line(doc, style, `${t.location}: ${formatLocation(finding.location)}`);
  line(doc, style, `${t.evidence}: ${finding.evidence}`);
  line(doc, style, `${labels.impact}: ${finding.impact}`);
  line(doc, style, `${labels.recommendation}: ${finding.recommendation}`);
  const details = findingDetails(finding, ctx);
  const guidance = ruleGuidance(finding, details, ctx.chrome);
  if (guidance.rationale !== null) line(doc, style, `${t.ruleRationale}: ${guidance.rationale}`);
  if (guidance.remediation !== null)
    line(doc, style, `${t.ruleRemediation}: ${guidance.remediation}`);
  if (details !== undefined && details.standards.length > 0) {
    linkLine(doc, style, t.standards, details.standards);
  }
  if (details !== undefined && details.examples.length > 0) {
    line(doc, style, t.examplesInAppendix, MUTED);
  }
  const references = [
    ...finding.references.cwe,
    ...finding.references.owasp,
    ...finding.references.cve,
  ];
  if (references.length > 0) line(doc, style, `${t.references}: ${references.join(", ")}`, MUTED);
}

function severityWord(severity: unknown, ctx: ReportContext): string {
  return word(ctx.t.severity, severity, ctx.t.unknownLabel);
}

function word(words: Readonly<Record<string, string>>, value: unknown, fallback?: string): string {
  if (typeof value === "string" && Object.hasOwn(words, value)) return words[value] ?? "";
  return fallback ?? String(value);
}

function writeStandardsCoverage(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  result: ScanResult,
  ctx: ReportContext,
): void {
  const t = ctx.t;
  heading(doc, style, t.standardsTitle);
  if (result.standardsCoverage === undefined) {
    line(doc, style, t.notRecorded, MUTED);
    return;
  }
  line(doc, style, t.standardsNote, MUTED);
  doc.moveDown(0.3);
  for (const row of owaspRows(result, ctx)) {
    const detail =
      row.state === "no_rules"
        ? row.reason
        : `${row.breadth}${row.rules === "" ? "" : ` (${row.rules})`}${row.state === "rules_ran" ? "" : `; ${row.reason}`}`;
    doc
      .font(style.regular)
      .fontSize(10)
      .fillColor(row.state === "rules_partial" ? "#b45309" : MUTED)
      .text(style.text(`[${row.stateLabel}] `), { continued: true })
      .fillColor("#1d4ed8")
      .text(style.text(row.id), { continued: true, link: row.url === "" ? undefined : row.url })
      .fillColor("#0f172a")
      .text(style.text(` ${row.title} - ${detail}`), { link: undefined });
  }
  doc.moveDown(0.3);
  line(doc, style, `${t.cweTop25Title}: ${cweTop25CountsText(result, ctx)}`);
}

function writeRuleStats(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  result: ScanResult,
  ctx: ReportContext,
): void {
  const t = ctx.t;
  if (result.ruleStats === undefined) return;
  heading(doc, style, `${t.appendixStats} - ${t.ruleStatsTitle(result.ruleStats.length)}`);
  line(doc, style, t.ruleStatsNote, MUTED);
  doc.moveDown(0.3);
  const columns = t.ruleStatsColumns;
  line(
    doc,
    style,
    `${columns.rule} | ${columns.area} | ${columns.targets} | ${columns.findings} | ${columns.status}`,
    MUTED,
  );
  for (const row of ruleStatRows(result, ctx)) {
    line(
      doc,
      style,
      `${row.ruleId}${row.title === "" ? "" : ` ${row.title}`} | ${row.area} | ${row.targets} | ${row.findings} | ${row.status}`,
    );
  }
  if (result.standardsCoverage !== undefined) {
    doc.moveDown(0.5);
    line(doc, style, `${t.cweTop25Title}`, MUTED);
    for (const row of cweTop25Rows(result, ctx)) {
      line(
        doc,
        style,
        `${row.rank ?? ""}. ${row.id} ${row.title} - ${row.stateLabel}${row.rules === "" ? "" : ` (${row.rules})`}`,
      );
    }
  }
}

function writeExamples(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  findings: readonly Finding[],
  ctx: ReportContext,
): void {
  const t = ctx.t;
  const rules = rulesWithExamples(findings, ctx);
  if (rules.length === 0) return;
  heading(doc, style, t.appendixExamples);
  for (const rule of rules) {
    doc.moveDown(0.4);
    doc
      .font(style.bold)
      .fontSize(10)
      .fillColor("#0f172a")
      .text(style.text(`${rule.ruleId} ${rule.title}`));
    for (const example of rule.details.examples) {
      line(doc, style, `${t.vulnerable} (${example.language})`, MUTED);
      codeBlock(doc, style, example.vulnerable);
      line(doc, style, t.safe, MUTED);
      codeBlock(doc, style, example.safe);
      if (example.note !== undefined) line(doc, style, example.note[ctx.chrome], MUTED);
    }
  }
}

function writeStandardsLinks(
  doc: PDFKit.PDFDocument,
  style: PdfStyle,
  findings: readonly Finding[],
  ctx: ReportContext,
): void {
  const links = standardsLinksOf(findings, ctx);
  if (links.length === 0) return;
  heading(doc, style, ctx.t.appendixLinks);
  for (const link of links) {
    doc
      .font(style.regular)
      .fontSize(9)
      .fillColor("#0f172a")
      .text(
        style.text(
          `${link.id}${link.title === null ? "" : ` ${link.title}`}${standardMark(link, ctx.t)}: `,
        ),
        {
          continued: true,
        },
      )
      .fillColor("#1d4ed8")
      .text(style.text(link.url), { link: link.url });
  }
}

/** Every string the PDF shows that is not part of the (already checked) result itself. */
function extraStrings(
  result: ScanResult,
  findings: readonly Finding[],
  ctx: ReportContext,
): unknown {
  return [
    ruleStatRows(result, ctx),
    // Only the texts that are printed: the catalog also holds the other language's text.
    findings.map((finding) => {
      const details = findingDetails(finding, ctx);
      if (details === undefined) return undefined;
      return {
        guidance: ruleGuidance(finding, details, ctx.chrome),
        standards: details.standards,
        examples: details.examples.map((example) => ({
          ...example,
          note: example.note?.[ctx.chrome],
        })),
      };
    }),
    standardsLinksOf(findings, ctx),
  ];
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
  const loaded = loadPdfFonts();
  const style = loaded.ok ? FONT_STYLE : LATIN_STYLE;
  // Without the Korean-capable font Korean text would print as "?": fall back to English for the
  // fixed words (`ctx.chrome`) and for the texts taken from the rule catalog alike.
  const languageOptions: ReportLanguageOptions = loaded.ok ? options : { ...options, lang: "en" };
  const result = prepareLocalizedReportResult(input, languageOptions);
  const ctx = reportContext(languageOptions);
  const t = ctx.t;
  options.onFontFallback?.(loaded.ok ? null : fontFallbackMessage(loaded.reason));
  // A code-only result (JSON 1.7) carries its "not authorized" banner on every page.
  const codeOnly = codeOnlyLabel(input, ctx.chrome);
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: "A4",
      compress: options.compress ?? true,
      // The banners are drawn once every page exists, so they never touch the font, size or
      // colour of the text that flows onto a new page.
      bufferPages: codeOnly !== null,
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
    const drawBanners = (): void => {
      if (codeOnly === null) return;
      const range = doc.bufferedPageRange();
      for (let page = range.start; page < range.start + range.count; page += 1) {
        doc.switchToPage(page);
        doc
          .save()
          .rect(0, 0, doc.page.width, PAGE_MARGIN - 14)
          .fill("#fef3c7")
          .restore();
        doc
          .font(style.bold)
          .fontSize(8)
          .fillColor("#78350f")
          .text(style.text(codeOnly.banner), PAGE_MARGIN, 14, {
            width: doc.page.width - PAGE_MARGIN * 2,
            lineBreak: false,
            ellipsis: true,
          });
      }
    };
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const target = result.target;
    // Headline counts cover regular code; test and fixture findings get their own section, and
    // suggestions in vendored code come last.
    const { primary, test, vendored, suppressed, baseline } = groupReportFindings(result.findings);
    const hasBaseline = result.baseline !== undefined;
    doc.font(style.bold).fontSize(20).fillColor("#0f172a").text(style.text(t.title));
    line(
      doc,
      style,
      `${t.repository}: ${target.repo ?? t.unknown} - ${t.revision}: ${target.revision ?? t.unknown}`,
      MUTED,
    );
    if (target.webOrigin !== null) line(doc, style, `${t.webTarget}: ${target.webOrigin}`, MUTED);
    line(
      doc,
      style,
      `${t.scan} ${result.scanId} - ${result.startedAt} ${t.to} ${result.finishedAt} - ${result.tool.name} ${result.tool.version} - ${t.schema} ${result.schemaVersion}`,
      MUTED,
    );
    line(doc, style, `${t.requestedScopes}: ${result.requestedScopes.join(", ") || t.none}`, MUTED);
    if (!loaded.ok) {
      doc.moveDown(0.3);
      line(doc, style, fontFallbackMessage(loaded.reason), "#b45309");
    }
    if (codeOnly !== null) {
      doc.moveDown(0.5);
      doc.font(style.bold).fontSize(13).fillColor("#78350f").text(style.text(codeOnly.title));
      line(doc, style, codeOnly.body, "#78350f");
      line(doc, style, codeOnly.reason, "#78350f");
    }
    const shown = [result, extraStrings(result, result.findings, ctx)];
    const hasReplacedText = loaded.ok
      ? hasStringOutsideFont(shown)
      : hasUnsupportedPdfCharacters(shown);
    if (hasReplacedText) {
      doc.moveDown(0.3);
      line(doc, style, loaded.ok ? PDF_FONT_REPLACEMENT_NOTICE : PDF_REPLACEMENT_NOTICE, "#b45309");
    }
    doc.moveDown(0.5);
    doc
      .font(style.bold)
      .fontSize(11)
      .fillColor("#0f172a")
      .text(
        style.text(`${t.overallStatus}: ${word(t.overall, result.overallStatus, t.unknownLabel)}`),
      );

    for (const notice of projectConfigNotices(result.coverage)) {
      if (notice.tone !== "warning") continue;
      doc.moveDown(0.3);
      line(doc, style, `${t.note}: ${notice.text}`, "#b45309");
    }
    for (const text of localizedSuppressionNotices(result, ctx)) {
      doc.moveDown(0.3);
      line(doc, style, `${t.note}: ${text}`, "#b45309");
    }
    heading(doc, style, t.summary);
    line(doc, style, summaryLine(result, ctx));
    const incremental = incrementalLine(result.incremental, ctx.chrome);
    if (incremental !== null) line(doc, style, `${incremental.label}: ${incremental.value}`, MUTED);
    doc.moveDown(0.5);
    drawSeverityBars(doc, style, primary, ctx);

    heading(doc, style, t.coverage);
    if (result.coverage.length === 0) line(doc, style, t.noCoverage);
    for (const entry of result.coverage) {
      line(
        doc,
        style,
        `${entry.area} (${entry.scope}): ${word(t.coverageStatus, entry.status, t.unknownLabel)}${entry.note === null ? "" : ` - ${entry.note}`}`,
      );
    }

    writeStandardsCoverage(doc, style, result, ctx);

    heading(doc, style, hasBaseline ? t.newFindings : t.findings);
    if (primary.length === 0) {
      line(
        doc,
        style,
        `${noFindingsLine({ test: test.length, vendored: vendored.length, suppressed }, hasBaseline, ctx)} ${t.noFindingsTailPdf}`,
      );
    }
    for (const finding of primary) writeFinding(doc, style, finding, ctx, hasBaseline);
    if (test.length > 0) {
      heading(doc, style, `${t.testTitle} (${test.length})`);
      line(
        doc,
        style,
        `${t.testNote}${ctx.chrome === "en" ? configTestGroupNote(result.coverage) : ""}`,
        MUTED,
      );
      for (const finding of test) writeFinding(doc, style, finding, ctx);
    }
    if (vendored.length > 0) {
      heading(doc, style, `${t.vendoredTitle} (${vendored.length})`);
      line(doc, style, t.vendoredNote);
      line(doc, style, t.vendoredDetail, MUTED);
      for (const finding of vendored) writeFinding(doc, style, finding, ctx);
    }

    // A PDF cannot collapse: suppressed and baseline findings are listed in full, after the rest.
    if (suppressed.length > 0) {
      heading(doc, style, `${t.suppressedTitle} (${suppressed.length})`);
      line(doc, style, t.suppressedNote, MUTED);
      for (const finding of suppressed) writeFinding(doc, style, finding, ctx);
    }
    if (baseline.length > 0) {
      heading(doc, style, `${t.baselineTitle} (${baseline.length})`);
      line(doc, style, t.baselineNote, MUTED);
      for (const finding of baseline) writeFinding(doc, style, finding, ctx);
    }

    heading(doc, style, t.authorization);
    line(doc, style, `${t.decision}: ${result.authorization.decision}`);
    for (const check of result.authorization.checks) {
      line(doc, style, `${check.id}: ${check.status} - ${check.reason}`);
    }

    heading(doc, style, t.analysisBasis);
    line(doc, style, t.analysisBasisNote);

    // Rule statistics, examples and the full links go in appendices, after the findings: they
    // are reference material that a PDF cannot collapse, and examples would repeat for every
    // finding of the same rule. The HTML report shows them inline in collapsible sections.
    const hasAppendix =
      result.ruleStats !== undefined ||
      rulesWithExamples(result.findings, ctx).length > 0 ||
      standardsLinksOf(result.findings, ctx).length > 0;
    if (hasAppendix) {
      doc.addPage();
      line(doc, style, t.appendixNote, MUTED);
    }
    writeRuleStats(doc, style, result, ctx);
    writeExamples(doc, style, result.findings, ctx);
    writeStandardsLinks(doc, style, result.findings, ctx);

    if (
      result.standardsCoverage !== undefined ||
      standardsLinksOf(result.findings, ctx).length > 0
    ) {
      heading(doc, style, t.licenseTitle);
      line(doc, style, t.licenseIntro, MUTED);
      for (const text of [t.licenseOwasp, t.licenseCwe, t.licenseCert]) {
        doc.font(style.regular).fontSize(8).fillColor(MUTED).text(style.text(text));
      }
    }

    doc.moveDown(1);
    doc.font(style.regular).fontSize(8).fillColor(MUTED).text(style.text(t.disclaimer));
    drawBanners();
    doc.end();
  });
}
