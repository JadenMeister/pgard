// corpus: expect=none
const crypto = require("node:crypto");

// Cache validator for a static file, not a credential.
function etag(buffer) {
  return crypto.createHash("md5").update(buffer).digest("hex");
}
module.exports = { etag };
