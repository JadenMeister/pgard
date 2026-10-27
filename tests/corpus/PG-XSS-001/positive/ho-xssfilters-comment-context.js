// corpus: expect=PG-XSS-001
import xssFilters from "xss-filters";
export function r(el) { el.innerHTML = xssFilters.inHTMLComment(location.hash); }
