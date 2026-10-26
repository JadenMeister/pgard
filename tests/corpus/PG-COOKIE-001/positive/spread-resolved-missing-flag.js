// corpus: expect=PG-COOKIE-001
const BASE = { httpOnly: true, secure: true };

module.exports = (req, res) => {
  res.cookie("session", issue(req), { ...BASE, maxAge: 3600000 });
  res.sendStatus(204);
};
