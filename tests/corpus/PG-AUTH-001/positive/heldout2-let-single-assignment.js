// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  let pw = req.body.pw;
  await User.create({ email: req.body.email, password: pw });
  res.sendStatus(201);
};
