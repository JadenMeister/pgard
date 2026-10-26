// corpus: expect=PG-AUTH-001
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  await User.create({ email, password });
  res.sendStatus(201);
});
