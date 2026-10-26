// corpus: expect=PG-CRYPTO-003
const crypto = require("crypto");

const ALGO = "des-ede3-cbc";

module.exports.open = (key, iv, data) => {
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
};
