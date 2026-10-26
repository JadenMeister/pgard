// corpus: expect=none
const jwt = require("jsonwebtoken");

function issue(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET);
}
module.exports = { issue };
