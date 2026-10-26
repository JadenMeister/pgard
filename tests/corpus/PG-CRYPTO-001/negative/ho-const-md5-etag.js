// corpus: expect=none
const crypto = require("crypto");

const ETAG_ALGO = "md5";

module.exports = (body) => `"${crypto.createHash(ETAG_ALGO).update(body).digest("base64")}"`;
