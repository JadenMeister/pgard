// corpus: expect=PG-XSS-001
async function renderComment(el: HTMLElement, id: string) {
  const res = await fetch("/api/comments/" + id);
  const body = await res.text();
  el.outerHTML = body;
}
export { renderComment };
