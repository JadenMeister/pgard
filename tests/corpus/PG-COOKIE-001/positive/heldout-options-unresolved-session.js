// corpus: expect=PG-COOKIE-001
// The options cannot be resolved, so the flags are unverified; for a session cookie that is reported at low confidence.
const { cookieOptions } = require("./config");

module.exports = (req, res) => {
  res.cookie("session", issue(req), { ...cookieOptions, maxAge: 3600000 });
  res.sendStatus(204);
};
