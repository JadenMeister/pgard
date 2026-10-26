// corpus: expect=none
const crypto = require("node:crypto");

module.exports = (key, data) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  return { iv, body: Buffer.concat([cipher.update(data), cipher.final()]), tag: cipher.getAuthTag() };
};
