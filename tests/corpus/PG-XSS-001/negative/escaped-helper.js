// corpus: expect=none
import escapeHtml from "escape-html";

export function show(el, name) {
  el.innerHTML = `<h1>Hello ${escapeHtml(name)}</h1>`;
}
