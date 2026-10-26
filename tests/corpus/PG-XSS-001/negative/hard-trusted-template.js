// corpus: expect=low
import template from "./templates/card.html?raw";

export function render(el) {
  // The template ships with the bundle; no request data reaches it.
  el.innerHTML = template;
}
