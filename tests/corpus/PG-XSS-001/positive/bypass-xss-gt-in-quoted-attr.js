// corpus: expect=PG-XSS-001
import esc from "escape-html";
export function link() {
  const url = new URLSearchParams(location.search).get("u");
  document.querySelector("#out").innerHTML = `<a title="next > prev" href="${esc(url)}">open</a>`;
}
