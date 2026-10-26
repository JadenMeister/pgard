// corpus: expect=none
const crypto = require("node:crypto");

// Gravatar identifies avatars by the md5 of the email; not a credential.
module.exports = (email) =>
  `https://www.gravatar.com/avatar/${crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex")}`;
