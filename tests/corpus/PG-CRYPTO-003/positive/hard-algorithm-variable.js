// corpus: expect=PG-CRYPTO-003
const crypto = require("node:crypto");
const ALGORITHM = "des-cbc";

module.exports = (key, iv, data) => {
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
};
