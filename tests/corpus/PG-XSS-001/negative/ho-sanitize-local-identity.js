// corpus: expect=low
// A local "sanitize" that returns its input proves nothing.
function sanitize(value) {
  return value;
}

export function showStatus(el) {
  el.innerHTML = sanitize(location.hash.slice(1));
}
