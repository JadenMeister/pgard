// corpus: expect=none
// The "?" inside the string literal is not a placeholder; the request value belongs to email.
module.exports = async (req, res) => {
  await db.run("INSERT INTO users (note, password, email) VALUES ('ok?', ?, ?)", [generated, req.body.email]);
  res.sendStatus(201);
};
