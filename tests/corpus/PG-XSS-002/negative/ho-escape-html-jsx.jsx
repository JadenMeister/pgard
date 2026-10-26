// corpus: expect=none
import escapeHtml from "escape-html";

export function Hello({ name }) {
  return <p dangerouslySetInnerHTML={{ __html: `Hello <b>${escapeHtml(name)}</b>` }} />;
}
