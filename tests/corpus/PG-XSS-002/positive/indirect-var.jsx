// corpus: expect=PG-XSS-002
export function Post({ post }) {
  const html = post.bodyHtml;
  const markup = { __html: html };
  return <article dangerouslySetInnerHTML={markup} />;
}
