// corpus: expect=none
import sanitizeHtml from "sanitize-html";

export function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />;
}
