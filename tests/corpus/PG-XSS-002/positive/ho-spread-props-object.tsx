// corpus: expect=PG-XSS-002
import { useEffect, useState } from "react";

export function Post({ slug }: { slug: string }) {
  const [content, setContent] = useState("");
  useEffect(() => {
    fetch(`/api/posts/${slug}`).then((r) => r.text()).then(setContent);
  }, [slug]);
  const bodyProps = { className: "prose", dangerouslySetInnerHTML: { __html: content } };
  return <article {...bodyProps} />;
}
