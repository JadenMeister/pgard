/**
 * Modules whose export, when it is the file's sole binding of that local name, fully suppresses
 * an XSS finding. A sanitizer found any other way (a local function, a re-export from a local
 * module, a global, a Vue method) is only inferred from its name and keeps a low-confidence finding.
 *
 * `escape-html` is deliberately absent: it escapes only `& < > " '`, so it demotes, never drops.
 */
export const TRUSTED_SANITIZER_MODULES: ReadonlySet<string> = new Set([
  "dompurify",
  "isomorphic-dompurify",
  "sanitize-html",
  "xss",
  "js-xss",
  "xss-filters",
  "insane",
]);

/** Member or direct call names that produce sanitized output on a trusted sanitizer module. */
export const TRUSTED_SANITIZER_METHOD =
  /^(sanitize\w*|filterXSS|xss|purify|(in|uriIn|uriPathIn|uriQueryIn|uriComponentIn|uriFragmentIn)[A-Z]\w*)$/;

/** Names that look like a sanitizer; a match without a proven import is inferred only. */
export const SANITIZER_NAME =
  /^(sanitize|sanitizeHtml|purify|escape|escapeHtml|encode|xss|filterXSS|htmlEscape)$/i;
