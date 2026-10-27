// corpus: expect=low
import purify from "./lib/purify";

export function render(el: HTMLElement, query: URLSearchParams) {
  el.innerHTML = purify.sanitize(query.get("html") ?? "");
}
