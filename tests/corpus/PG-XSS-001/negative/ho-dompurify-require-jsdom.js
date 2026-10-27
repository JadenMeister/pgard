// corpus: expect=none
const createDOMPurify = require("dompurify");
const { JSDOM } = require("jsdom");

const purify = createDOMPurify(new JSDOM("").window);

module.exports = function render(el, html) {
  el.innerHTML = purify.sanitize(html);
};
