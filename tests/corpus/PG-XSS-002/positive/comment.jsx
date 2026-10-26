// corpus: expect=PG-XSS-002
export function Comment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: comment }} />;
}
