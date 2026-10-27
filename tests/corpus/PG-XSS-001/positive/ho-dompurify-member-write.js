// corpus: expect=PG-XSS-001
import DOMPurify from "dompurify";
DOMPurify.sanitize = (s) => s;
export function r(el) { el.innerHTML = DOMPurify.sanitize(location.hash); }
