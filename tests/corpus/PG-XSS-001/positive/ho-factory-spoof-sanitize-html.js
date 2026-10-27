// corpus: expect=PG-XSS-001
import sanitizeHtml from "sanitize-html";
const purify = sanitizeHtml("x");
export function r(el) { el.innerHTML = purify.sanitize(location.hash); }
