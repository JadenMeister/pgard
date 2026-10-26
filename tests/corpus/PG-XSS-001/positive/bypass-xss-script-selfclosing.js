// corpus: expect=PG-XSS-001
import esc from "escape-html";
const q = new URLSearchParams(location.search).get("q");
document.write("<div><script/>run(" + esc(q) + ")</script></div>");
