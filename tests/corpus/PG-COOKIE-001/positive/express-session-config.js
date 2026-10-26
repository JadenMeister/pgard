// corpus: expect=PG-COOKIE-001
const session = require("express-session");

module.exports = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 },
});
