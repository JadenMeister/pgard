// corpus: expect=none
const crypto = require("crypto");
const config = require("./config");

let algo = "md5";
algo = config.hashAlgorithm;

module.exports = (password) => crypto.createHash(algo).update(password).digest("hex");
