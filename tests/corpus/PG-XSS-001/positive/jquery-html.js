// corpus: expect=PG-XSS-001; known=miss:PG-XSS-001:jQuery .html() is not among the recognised sinks
import $ from "jquery";

$("#search").on("input", function () {
  const term = $(this).val();
  $("#results").html("No results for " + term);
});
