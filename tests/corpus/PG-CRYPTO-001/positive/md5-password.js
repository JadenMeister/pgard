// corpus: expect=PG-CRYPTO-001
const crypto = require("node:crypto");

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}
module.exports = { hashPassword };
