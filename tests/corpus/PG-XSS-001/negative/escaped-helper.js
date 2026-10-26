// corpus: expect=none; known=fp:PG-XSS-001:an escape-html call is not recognised as a sanitizer
import escapeHtml from "escape-html";

export function show(el, name) {
  el.innerHTML = `<h1>Hello ${escapeHtml(name)}</h1>`;
}
