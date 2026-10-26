// corpus: expect=PG-AUTH-001; known=miss:PG-AUTH-001:a password assigned as a property on a model instance before .save() is not recognised
module.exports = async function register(req, res) {
  const user = new User();
  user.email = req.body.email;
  user.password = req.body.password;
  await user.save();
  res.sendStatus(201);
};
