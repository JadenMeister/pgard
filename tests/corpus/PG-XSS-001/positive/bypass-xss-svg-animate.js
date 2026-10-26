// corpus: expect=PG-XSS-001
import esc from "escape-html";
export function badge(el) {
  const target = location.hash.slice(1);
  el.innerHTML = `<svg><a><animate attributeName="href" values="${esc(target)}"/><text y="20">go</text></a></svg>`;
}
