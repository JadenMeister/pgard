// corpus: expect=none
const crypto = require("node:crypto");

module.exports = (key, data) => {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([iv, c.update(data), c.final()]);
};
