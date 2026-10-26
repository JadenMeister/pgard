// corpus: expect=none
const { secure } = require("./secrets");

module.exports = async (req, res) => {
  const user = new User();
  user.password = secure(req.body.password);
  await user.save();
  res.sendStatus(201);
};
