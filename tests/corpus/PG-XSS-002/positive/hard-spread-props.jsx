// corpus: expect=PG-XSS-002; known=miss:PG-XSS-002:dangerouslySetInnerHTML supplied through a spread props object is not recognised
export function Rich({ html }) {
  const props = { dangerouslySetInnerHTML: { __html: html } };
  return <div {...props} />;
}
