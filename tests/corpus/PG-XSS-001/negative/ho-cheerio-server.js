// corpus: expect=none
// Server-side cheerio: `$` is not jQuery and `.html()` builds a string, it is not a DOM sink.
const cheerio = require("cheerio");

module.exports = (page, title) => {
  const $ = cheerio.load(page);
  $("title").html(title);
  return $.html();
};
