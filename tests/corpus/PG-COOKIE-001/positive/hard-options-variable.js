// corpus: expect=PG-COOKIE-001
const opts = { httpOnly: true };

module.exports = (req, res) => {
  res.cookie("session", issue(req), opts);
  res.sendStatus(204);
};
