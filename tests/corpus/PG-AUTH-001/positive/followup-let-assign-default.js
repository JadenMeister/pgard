// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  let password;
  password = req.body.password || "";
  await User.create({ email: req.body.email, password });
  res.sendStatus(201);
};
