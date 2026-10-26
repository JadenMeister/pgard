// corpus: expect=none
const { cookieOptions } = require("./config");

module.exports = (req, res) => {
  res.cookie("session", issue(req), { ...cookieOptions, maxAge: 3600000 });
  res.sendStatus(204);
};
