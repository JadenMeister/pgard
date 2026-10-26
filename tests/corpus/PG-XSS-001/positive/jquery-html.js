// corpus: expect=PG-XSS-001; known=miss:PG-XSS-001:jQuery .html() is not among the recognised sinks
import $ from "jquery";

const term = new URLSearchParams(location.search).get("q");
$("#results").html("No results for " + term);
