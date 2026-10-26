// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  await db.run("INSERT INTO users (email, password) VALUES (@email, @password)", { email: req.body.email, password: req.body.password });
  res.sendStatus(201);
};
