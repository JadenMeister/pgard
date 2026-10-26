// corpus: expect=none
import $ from "jquery";

export function show(id, name, node) {
  $("#row-" + id).addClass("selected");
  $("#name").text(name);
  $("#holder").append(document.createTextNode(name));
  $("#holder").append(node);
  $("#banner").html("<b>Saved</b>");
}
