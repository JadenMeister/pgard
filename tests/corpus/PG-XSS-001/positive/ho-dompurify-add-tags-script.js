// corpus: expect=PG-XSS-001
import DOMPurify from "dompurify";

// A sanitizer configured to keep <script> is no sanitizer.
export function render(el) {
  el.innerHTML = DOMPurify.sanitize(location.hash, { ADD_TAGS: ["script"] });
}
