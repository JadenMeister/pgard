// corpus: expect=PG-XSS-001
import escapeHtml from "escape-html";
import { marked } from "marked";

// escape-html is imported, but the value rendered here never went through it.
export function render(el, title) {
  el.innerHTML = "<h1>" + escapeHtml(title) + "</h1>" + marked(location.hash);
}
