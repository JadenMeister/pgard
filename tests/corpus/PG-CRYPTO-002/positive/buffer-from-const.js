// corpus: expect=PG-CRYPTO-002
const jwt = require("jsonwebtoken");

const SECRET = "buffer-wrapped-signing-secret";

module.exports.issue = (user) => jwt.sign({ sub: user.id }, Buffer.from(SECRET));
