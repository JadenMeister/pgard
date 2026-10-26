// corpus: expect=PG-XSS-001
import esc from "escape-html";
export function loadCallback() {
  const cb = new URLSearchParams(location.search).get("cb");
  const s = document.createElement("script");
  s.innerHTML = esc(cb);
  document.head.appendChild(s);
}
