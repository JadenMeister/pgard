// corpus: expect=PG-AUTH-001
module.exports = async function register(req, res) {
  const user = new User();
  user.email = req.body.email;
  user.password = req.body.password;
  await user.save();
  res.sendStatus(201);
};
