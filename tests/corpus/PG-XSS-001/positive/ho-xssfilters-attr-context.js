// corpus: expect=PG-XSS-001
import { inDoubleQuotedAttr } from "xss-filters";
export function r(el) { el.innerHTML = inDoubleQuotedAttr(location.hash); }
