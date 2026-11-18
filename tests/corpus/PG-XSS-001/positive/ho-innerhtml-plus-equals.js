// corpus: expect=PG-XSS-001
export function log(el, message) {
  el.innerHTML += "<li>" + message + location.hash + "</li>";
}
