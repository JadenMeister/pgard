// corpus: expect=none
const argon2 = require("argon2");

module.exports = async (req, res) => {
  const user = new User();
  user.email = req.body.email;
  user.password = await argon2.hash(req.body.password);
  await user.save();
  res.sendStatus(201);
};
