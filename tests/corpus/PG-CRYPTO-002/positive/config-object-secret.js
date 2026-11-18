// corpus: expect=PG-CRYPTO-002
const jwt = require("jsonwebtoken");

const config = { port: 3000, jwt: "x", secret: "config-object-signing-secret" };

module.exports.issue = (user) => jwt.sign({ sub: user.id }, config.secret);
