// corpus: expect=none
import $ from "jquery";

// .text() returns a jQuery object, not a string: tainted text is appended as a node.
$("#list").append($("<li>").text(location.hash));
$("#list").append(document.createElement("li"));
