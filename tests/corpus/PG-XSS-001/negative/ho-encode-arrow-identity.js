// corpus: expect=low
const encode = (s) => s;

export function showName(el, params) {
  el.innerHTML = `<b>${encode(params.get("name"))}</b>`;
}
