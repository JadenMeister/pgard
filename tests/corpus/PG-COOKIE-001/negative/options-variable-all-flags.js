// corpus: expect=none
const OPTIONS = { httpOnly: true, secure: true, sameSite: "lax" };

module.exports = (req, res) => {
  res.cookie("session", issue(req), OPTIONS);
  res.sendStatus(204);
};
