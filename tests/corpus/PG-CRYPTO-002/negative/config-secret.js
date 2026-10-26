// corpus: expect=none
const session = require("express-session");
const config = require("./config");

module.exports = session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: "lax" },
});
