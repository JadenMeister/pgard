// corpus: expect=low
import cardTemplate from "../views/card.html";

export function mount(el: HTMLElement) {
  // The markup is a build-time asset; its content is not visible to the scan.
  el.innerHTML = cardTemplate;
}
