// corpus: expect=PG-XSS-002
import { marked } from "marked";

export function Readme({ markdown }) {
  return <div className="readme" dangerouslySetInnerHTML={{ __html: marked(markdown) }} />;
}
