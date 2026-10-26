// corpus: expect=PG-XSS-001
import esc from "escape-html";
const q = new URLSearchParams(location.search).get("q");
const s = document.createElement("script");
s.innerHTML = "var label = '<b>'; show(" + esc(q) + ");";
document.head.appendChild(s);
