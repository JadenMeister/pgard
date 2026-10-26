// corpus: expect=PG-XSS-001
import esc from "escape-html";
const q = new URLSearchParams(location.search).get("q");
import $ from "jquery";
$("#widget").html('<script>var tpl = "<b>"; track(' + esc(q) + ");</script>");
