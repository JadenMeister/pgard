export { escapeHtml, markInvisibleCharacters } from "./escape-html.js";
export {
  countFindingsBySeverity,
  ANALYSIS_BASIS_NOTE,
  formatContextCounts,
  formatVendoredSuggestions,
  formatFindingSummary,
  formatNoFindings,
  formatSuppressionReason,
  reportSuppressionNotices,
  BASELINE_FINDINGS_NOTE,
  BASELINE_FINDINGS_TITLE,
  SUPPRESSED_FINDINGS_NOTE,
  SUPPRESSED_FINDINGS_TITLE,
  formatLocation,
  formatOutsideContexts,
  groupReportFindings,
  labelCoverageStatus,
  labelOverallStatus,
  labelSeverity,
  MAX_EVIDENCE_CHARS,
  MAX_FIELD_CHARS,
  prepareReportResult,
  REPORT_DISCLAIMER,
  severityColor,
  sortFindings,
  summarizeStatusSplit,
  TEST_FINDINGS_NOTE,
  TEST_FINDINGS_TITLE,
  truncateField,
  TRUNCATION_MARKER,
  VENDORED_FINDINGS_DETAIL,
  VENDORED_FINDINGS_NOTE,
  VENDORED_FINDINGS_TITLE,
  FINDING_LABELS,
  type ReportLanguageOptions,
  type SeverityCounts,
} from "./format.js";
export { REPORT_TEXT, type NoticeTexts, type ReportText } from "./report-text.js";
export { standardMark } from "./report-view.js";
export { codeOnlyLabel, type CodeOnlyLabel } from "./code-only-text.js";
export { INCREMENTAL_TEXT, incrementalLine, type IncrementalText } from "./incremental-text.js";
export { isPdfFontCodePoint } from "./pdf-font.js";
export { renderHtmlReport, renderSeverityBarChartSvg } from "./render-html.js";
export {
  hasUnsupportedPdfCharacters,
  PDF_FONT_REPLACEMENT_NOTICE,
  PDF_REPLACEMENT_NOTICE,
  renderPdfReport,
  toPdfText,
} from "./render-pdf.js";
export {
  buildReportBaseName,
  isPathInsideDirectory,
  isReportFormat,
  renderReport,
  REPORT_FORMATS,
  ReportWriteError,
  writeReports,
  type ReportFormat,
  type ReportWriteErrorCode,
  type WriteReportsOptions,
  type WrittenReport,
} from "./write-report.js";
