// corpus: expect=PG-XSS-001
function showReferrer() {
  const q = decodeURIComponent(location.hash.slice(1));
  document.write("<p>You searched for " + q + "</p>");
}
showReferrer();
