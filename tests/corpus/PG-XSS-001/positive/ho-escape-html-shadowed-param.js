// corpus: expect=PG-XSS-001
import escapeHtml from "escape-html";

// The parameter shadows the import: this escapeHtml is not escape-html and must not be trusted.
export function render(el, escapeHtml) {
  el.innerHTML = "<p>" + escapeHtml(location.hash) + "</p>";
}
