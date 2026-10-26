// corpus: expect=none
const argon2 = require("argon2");

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  await User.create({ email, passwordHash: await argon2.hash(password) });
  res.sendStatus(201);
});
