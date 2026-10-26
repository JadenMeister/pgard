// corpus: expect=none
const crypto = require("crypto");

const ALGORITHM = "des-cbc";

exports.legacyName = () => ALGORITHM;

exports.seal = function (ALGORITHM, key, iv, data) {
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
};
