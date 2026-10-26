// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  await new Account({ email: req.body.email, password: req.body.password }).save();
  res.sendStatus(201);
};
