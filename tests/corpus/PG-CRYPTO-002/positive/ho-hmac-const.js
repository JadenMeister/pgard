// corpus: expect=PG-CRYPTO-002
const crypto = require("crypto");

const SIGNING_KEY = "webhook-signing-key-2020";

module.exports = (payload) =>
  crypto.createHmac("sha256", SIGNING_KEY).update(payload).digest("hex");
