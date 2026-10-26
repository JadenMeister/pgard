// corpus: expect=PG-XSS-001
const q = new URLSearchParams(location.search).get("q");
let message = "Nothing found";
if (q) message = "No results for " + q;
document.querySelector("#msg").innerHTML = message;
