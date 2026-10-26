// corpus: expect=none
// The request value is bound to email, not to the password column.
module.exports = async (req, res) => {
  await pool.query("INSERT INTO users (password, email) VALUES ($1, $2)", [generated, req.body.email]);
  res.sendStatus(201);
};
