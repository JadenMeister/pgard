// corpus: expect=PG-CRYPTO-003; known=miss:PG-CRYPTO-003:a cipher name held in a constant is not resolved
const crypto = require("node:crypto");
const ALGORITHM = "des-cbc";

module.exports = (key, iv, data) => {
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
};
