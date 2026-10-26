// corpus: expect=PG-CRYPTO-002
const jwt = require("jsonwebtoken");

function issue(payload) {
  return jwt.sign(payload, "my-secret-key");
}
module.exports = { issue };
