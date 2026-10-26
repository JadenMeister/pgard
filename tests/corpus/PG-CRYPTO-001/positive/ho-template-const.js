// corpus: expect=PG-CRYPTO-001
const { createHash } = require("node:crypto");

const DIGEST = `sha1`;

exports.storePassword = (user) => {
  user.passwordHash = createHash(DIGEST).update(user.password).digest("hex");
  return user;
};
