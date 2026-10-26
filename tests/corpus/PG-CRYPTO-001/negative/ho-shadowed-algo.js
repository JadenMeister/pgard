// corpus: expect=none
const crypto = require("crypto");

const ALGORITHM = "md5";

function describe() {
  return ALGORITHM;
}

function digest(password, ALGORITHM) {
  return crypto.createHash(ALGORITHM).update(password).digest("hex");
}

module.exports = { describe, digest };
