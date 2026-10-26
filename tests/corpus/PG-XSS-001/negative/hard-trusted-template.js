// corpus: expect=none; known=fp:PG-XSS-001:assigning an imported (bundled) template string to innerHTML is reported
import template from "./templates/card.html?raw";

export function render(el) {
  // The template ships with the bundle; no request data reaches it.
  el.innerHTML = template;
}
