// corpus: expect=none
import DOMPurify from "dompurify";

export function Note({ html }) {
  const bodyProps = { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(html) } };
  return <div {...bodyProps} />;
}
