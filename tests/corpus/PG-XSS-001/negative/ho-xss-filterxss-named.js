// corpus: expect=none
import { filterXSS } from "xss";

export function render(el, input) {
  el.innerHTML = filterXSS(input);
}
