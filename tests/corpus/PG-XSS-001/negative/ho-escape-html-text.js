// corpus: expect=low
import escapeHtml from "escape-html";

export function renderItem(list, item) {
  const li = document.createElement("li");
  li.innerHTML = `<strong>${escapeHtml(item.name)}</strong> <span>${escapeHtml(item.note)}</span>`;
  list.appendChild(li);
}
