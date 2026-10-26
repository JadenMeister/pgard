// corpus: expect=PG-CRYPTO-003
const crypto = require("node:crypto");

module.exports = (key, data) => {
  const c = crypto.createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([c.update(data), c.final()]);
};
