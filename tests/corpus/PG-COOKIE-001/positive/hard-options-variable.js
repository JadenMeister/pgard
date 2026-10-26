// corpus: expect=PG-COOKIE-001; known=miss:PG-COOKIE-001:cookie options held in a variable are not resolved
const opts = { httpOnly: true };

module.exports = (req, res) => {
  res.cookie("session", issue(req), opts);
  res.sendStatus(204);
};
