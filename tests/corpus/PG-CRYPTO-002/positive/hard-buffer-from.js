// corpus: expect=PG-CRYPTO-002
const crypto = require("node:crypto");

module.exports = (body) =>
  crypto.createHmac("sha256", Buffer.from("static-webhook-signing-key")).update(body).digest("hex");
