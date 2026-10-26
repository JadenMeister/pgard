// corpus: expect=PG-XSS-001
import esc from "escape-html";
const dest = new URLSearchParams(location.search).get("to");
document.write(`<meta http-equiv="refresh" content="0;url=${esc(dest)}">`);
