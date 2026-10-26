// corpus: expect=PG-XSS-001
import escapeHtml from "escape-html";

// escape-html does not protect an unquoted attribute or a URL: javascript:alert(1) passes through.
export function link(el, url, label) {
  el.innerHTML = `<a href=${escapeHtml(url)}>${escapeHtml(label)}</a>`;
}
