// corpus: expect=none
module.exports = async function request(req, res) {
  await Token.create({ email: req.body.email, token: randomToken(), expiresAt: Date.now() + 600000 });
  res.sendStatus(202);
};
