// corpus: expect=low
import DOMPurify from "dompurify";

export function paint(el, DOMPurify, html) {
  // The parameter shadows the import: this is whatever the caller passed.
  el.innerHTML = DOMPurify.sanitize(html);
}
