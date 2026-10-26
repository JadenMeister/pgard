// corpus: expect=none
import DOMPurify from "dompurify";

export function Comment({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
