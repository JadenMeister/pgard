// corpus: expect=PG-CRYPTO-003
const crypto = require("node:crypto");

function encrypt(key, iv, data) {
  const cipher = crypto.createCipheriv("des-ede3-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
module.exports = { encrypt };
