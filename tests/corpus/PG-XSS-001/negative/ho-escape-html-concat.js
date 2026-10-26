// corpus: expect=low
const escapeHtml = require("escape-html");

module.exports = function showFlash(box, message) {
  box.innerHTML = '<div class="flash" title="' + escapeHtml(message) + '">' + escapeHtml(message) + "</div>";
};
