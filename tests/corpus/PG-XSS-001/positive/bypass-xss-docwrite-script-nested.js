// corpus: expect=PG-XSS-001
import esc from "escape-html";
const q = new URLSearchParams(location.search).get("q");
document.write("<script>window.cfg = { label: '<span class=\"x\">' }; init(" + esc(q) + ")</script>");
