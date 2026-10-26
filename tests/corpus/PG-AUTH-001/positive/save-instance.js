// corpus: expect=PG-AUTH-001; known=miss:PG-AUTH-001:new Model({password}) followed by .save() is not recognised
module.exports = async function register(req, res) {
  const user = new User({ email: req.body.email, password: req.body.password });
  await user.save();
  res.sendStatus(201);
};
