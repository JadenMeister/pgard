// corpus: expect=PG-XSS-001
$(function () {
  var greeting = decodeURIComponent(location.hash.slice(1));
  $("#welcome").html("<b>Welcome back, " + greeting + "</b>");
});
