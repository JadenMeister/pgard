// corpus: expect=PG-XSS-001
import $ from "jquery";

const params = new URLSearchParams(location.search);
const $out = $("#search-output");

export function render() {
  $out.html(`<p>Results for <em>${params.get("q")}</em></p>`);
}
