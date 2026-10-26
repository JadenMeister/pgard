// corpus: expect=PG-XSS-001
import $ from "jquery";

const term = new URLSearchParams(location.search).get("q");
$("#results").html("No results for " + term);
