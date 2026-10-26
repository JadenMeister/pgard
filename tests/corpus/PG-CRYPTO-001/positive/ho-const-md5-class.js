// corpus: expect=PG-CRYPTO-001
const crypto = require("crypto");

const ALG = "md5";

class Users {
  static digest(password) {
    return crypto.createHash(ALG).update(password).digest("hex");
  }
}

module.exports = Users;
