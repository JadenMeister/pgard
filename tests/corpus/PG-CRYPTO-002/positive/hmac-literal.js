// corpus: expect=PG-CRYPTO-002
const crypto = require("node:crypto");

function signWebhook(body) {
  return crypto.createHmac("sha256", "webhook-signing-key-2024").update(body).digest("hex");
}
module.exports = { signWebhook };
