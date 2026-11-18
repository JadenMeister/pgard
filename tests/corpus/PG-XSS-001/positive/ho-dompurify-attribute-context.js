// corpus: expect=PG-XSS-001
import DOMPurify from "dompurify";

// HTML sanitizing does not make a value safe inside an attribute or a URL.
export function link(el) {
  el.innerHTML = "<a href='" + DOMPurify.sanitize(location.hash) + "'>open</a>";
}
