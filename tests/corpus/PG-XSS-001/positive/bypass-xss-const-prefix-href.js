// corpus: expect=PG-XSS-001
import esc from "escape-html";
const OPEN_LINK = '<a class="next" href="';
export function renderNext() {
  const next = new URLSearchParams(location.search).get("next");
  document.getElementById("nav").innerHTML = OPEN_LINK + esc(next) + '">Continue</a>';
}
