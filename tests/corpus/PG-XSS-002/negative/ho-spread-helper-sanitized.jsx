// corpus: expect=none
import DOMPurify from "dompurify";

function htmlProps(html) {
  return { className: "rich", dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(html) } };
}

export function Article({ html }) {
  return <section {...htmlProps(html)} />;
}
