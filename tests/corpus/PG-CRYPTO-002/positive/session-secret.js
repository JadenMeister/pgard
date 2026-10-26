// corpus: expect=PG-CRYPTO-002
const session = require("express-session");

module.exports = session({
  secret: "keyboard cat dev secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: "lax" },
});
