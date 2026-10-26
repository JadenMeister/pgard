// corpus: expect=PG-CRYPTO-001
const crypto = require("node:crypto");
const ALGORITHM = "md5";

module.exports = (password) => crypto.createHash(ALGORITHM).update(password).digest("hex");
