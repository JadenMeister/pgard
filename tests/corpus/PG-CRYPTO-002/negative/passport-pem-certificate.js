// corpus: expect=none
const { Strategy } = require("passport-jwt");

const CERT = `-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
-----END CERTIFICATE-----`;

module.exports = new Strategy({ secretOrKey: CERT, jwtFromRequest: extract }, verify);
