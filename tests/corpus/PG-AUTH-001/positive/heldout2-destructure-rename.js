// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  const { email, password: plain } = req.body;
  await User.create({ email, password: plain });
  res.sendStatus(201);
};
