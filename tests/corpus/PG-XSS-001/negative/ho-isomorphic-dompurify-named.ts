// corpus: expect=none
import { sanitize } from "isomorphic-dompurify";

export function render(el: HTMLElement, html: string) {
  const clean = sanitize(html);
  el.innerHTML = clean;
}
