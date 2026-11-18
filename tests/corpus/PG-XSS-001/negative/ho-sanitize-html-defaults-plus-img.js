// corpus: expect=none
import sanitizeHtml from "sanitize-html";

export function render(el, html) {
  el.innerHTML = sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
    allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, img: ["src", "alt"] },
  });
}
