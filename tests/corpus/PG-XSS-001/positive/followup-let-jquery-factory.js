// corpus: expect=PG-XSS-001
// A jQuery factory bound by a late assignment is still jQuery.
let $;
$ = require("jquery");
$("#out").html(location.hash);
