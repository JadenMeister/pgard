// corpus: expect=low
// DOMPurify comes from a <script> tag: nothing here shows which function it is.
export function render(el) {
  el.innerHTML = DOMPurify.sanitize(location.hash);
}
