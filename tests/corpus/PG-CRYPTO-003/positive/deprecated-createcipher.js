// corpus: expect=PG-CRYPTO-003
const crypto = require("node:crypto");

module.exports = (password, data) => {
  const c = crypto.createCipher("aes192", password);
  return c.update(data, "utf8", "hex") + c.final("hex");
};
