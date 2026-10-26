// corpus: expect=PG-XSS-001
import $ from "jquery";

export function loadComments(postId) {
  $.getJSON("/api/posts/" + postId + "/comments", function (comments) {
    comments.forEach(function (item) {
      $("#comments").append("<li class='c'>" + item.author + ": " + item.text + "</li>");
    });
  });
}
