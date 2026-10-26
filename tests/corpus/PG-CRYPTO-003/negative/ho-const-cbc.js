// corpus: expect=none
const crypto = require("crypto");

const ALGO = "aes-256-cbc";

module.exports = (key, iv, data) => {
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
};
