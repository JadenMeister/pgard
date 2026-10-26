// corpus: expect=none
const crypto = require("crypto");

module.exports = (options, key, iv, data) => {
  const cipher = crypto.createCipheriv(options.algorithm, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
};
