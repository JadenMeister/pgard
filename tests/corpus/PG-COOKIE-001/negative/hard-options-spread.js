// corpus: expect=none
const SECURE = { httpOnly: true, secure: true, sameSite: "strict" };

module.exports = (req, res) => {
  res.cookie("session", issue(req), { ...SECURE, maxAge: 3600000 });
  res.sendStatus(204);
};
