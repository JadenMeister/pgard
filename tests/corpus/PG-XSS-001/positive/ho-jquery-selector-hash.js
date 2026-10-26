// corpus: expect=PG-XSS-001
// Classic: a location.hash that starts with "<" is parsed as HTML by jQuery.
$(window).on("hashchange", function () {
  $(location.hash).addClass("active");
});
