// corpus: expect=PG-CRYPTO-001; known=miss:PG-CRYPTO-001:an algorithm name held in a constant is not resolved
const crypto = require("node:crypto");
const ALGORITHM = "md5";

module.exports = (password) => crypto.createHash(ALGORITHM).update(password).digest("hex");
