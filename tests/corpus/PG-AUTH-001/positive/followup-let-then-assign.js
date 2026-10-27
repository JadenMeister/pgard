// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  let v;
  v = req.body.pw;
  await User.create({ email: req.body.email, password: v });
  res.sendStatus(201);
};
