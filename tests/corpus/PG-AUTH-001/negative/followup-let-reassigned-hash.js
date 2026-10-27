// corpus: expect=none; known=fp:PG-AUTH-001:a destructured let reassigned from a hashing helper is still treated as the plain request password
module.exports = async (req, res) => {
  let { password } = req.body;
  password = await protect(password);
  await User.create({ email: req.body.email, password });
  res.sendStatus(201);
};
