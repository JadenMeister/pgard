// corpus: expect=none
const fs = require("node:fs");
const jwt = require("jsonwebtoken");
const key = fs.readFileSync("/run/secrets/jwt_key");

module.exports = (payload) => jwt.sign(payload, key, { algorithm: "HS256" });
