// corpus: expect=PG-XSS-001
export function renderList(el, items) {
  const html = items.map((item) => `<li>${item.title}</li>`).join("");
  el.innerHTML = `<ul>${html}</ul>`;
}
