// corpus: expect=PG-XSS-001
import sanitizeHtml from "sanitize-html";

export function render(el) {
  el.innerHTML = sanitizeHtml(location.hash, {
    allowedTags: [...sanitizeHtml.defaults.allowedTags, "script"],
  });
}
