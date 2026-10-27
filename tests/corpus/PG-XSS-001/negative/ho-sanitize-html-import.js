// corpus: expect=none
import sanitizeHtml from "sanitize-html";

export function render(el, html) {
  el.innerHTML = sanitizeHtml(html);
}
