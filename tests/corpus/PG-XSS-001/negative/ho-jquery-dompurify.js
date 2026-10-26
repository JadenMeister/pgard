// corpus: expect=none
import $ from "jquery";
import DOMPurify from "dompurify";

$.get("/api/about", function (data) {
  $("#about").html(DOMPurify.sanitize(data));
});
