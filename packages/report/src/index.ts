export { escapeHtml, markInvisibleCharacters } from "./escape-html.js";
export {
  countFindingsBySeverity,
  formatAdvisoryDb,
  formatLocation,
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
  truncateField,
  TRUNCATION_MARKER,
  type SeverityCounts,
} from "./format.js";
export { renderHtmlReport, renderSeverityBarChartSvg } from "./render-html.js";
export {
  hasUnsupportedPdfCharacters,
  PDF_REPLACEMENT_NOTICE,
  renderPdfReport,
  toPdfText,
} from "./render-pdf.js";
export {
  buildReportBaseName,
  isPathInsideDirectory,
  isReportFormat,
  REPORT_FORMATS,
  ReportWriteError,
  writeReports,
  type ReportFormat,
  type ReportWriteErrorCode,
  type WriteReportsOptions,
  type WrittenReport,
} from "./write-report.js";
