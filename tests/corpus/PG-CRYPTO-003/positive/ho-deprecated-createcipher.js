// corpus: expect=PG-CRYPTO-003
const crypto = require("crypto");

module.exports = (password, data) => {
  const cipher = crypto.createCipher("aes192", password);
  return cipher.update(data, "utf8", "hex") + cipher.final("hex");
};
