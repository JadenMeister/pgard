// corpus: expect=PG-XSS-002
function htmlProps(html) {
  return { className: "rich", dangerouslySetInnerHTML: { __html: html } };
}

export function Article({ html }) {
  return <section {...htmlProps(html)} />;
}
