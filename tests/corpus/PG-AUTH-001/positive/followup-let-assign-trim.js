// corpus: expect=PG-AUTH-001
// The sole assignment is not a bare request read, but the password name still marks it plain.
module.exports = async (req, res) => {
  let password;
  password = req.body.password.trim();
  await User.create({ email: req.body.email, password });
  res.sendStatus(201);
};
