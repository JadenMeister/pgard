// corpus: expect=none
const bcrypt = require("bcrypt");

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}
module.exports = { hashPassword };
