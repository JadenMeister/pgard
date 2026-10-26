// corpus: expect=none
export function Footer() {
  return <footer {...{ dangerouslySetInnerHTML: { __html: "&copy; 2020 Example" } }} />;
}
