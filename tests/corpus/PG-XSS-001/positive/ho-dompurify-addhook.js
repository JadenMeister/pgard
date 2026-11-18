// corpus: expect=PG-XSS-001
import DOMPurify from "dompurify";

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  node.setAttribute("onclick", "track()");
});

export function render(el) {
  el.innerHTML = DOMPurify.sanitize(location.hash);
}
