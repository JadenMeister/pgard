// corpus: expect=PG-XSS-002
export function Article({ html }) {
  return <section {...{ dangerouslySetInnerHTML: { __html: html } }} />;
}
