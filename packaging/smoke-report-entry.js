// Smoke-test entry (not part of the public API): lets the pack smoke test reach the PDF font
// loader and renderer inside the installed package by file path.
export { loadPdfFonts } from "../packages/report/dist/pdf-font.js";
export { renderPdfReport, PDF_REPLACEMENT_NOTICE } from "../packages/report/dist/render-pdf.js";
