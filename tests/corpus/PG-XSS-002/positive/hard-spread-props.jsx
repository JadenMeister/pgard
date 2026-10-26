// corpus: expect=PG-XSS-002
export function Rich({ html }) {
  const props = { dangerouslySetInnerHTML: { __html: html } };
  return <div {...props} />;
}
