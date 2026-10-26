// corpus: expect=none
const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;

module.exports = (payload) => jwt.sign(payload, SECRET, { expiresIn: "1h" });
