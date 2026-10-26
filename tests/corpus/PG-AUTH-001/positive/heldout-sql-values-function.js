// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  await pool.query("INSERT INTO users (email, created_at, password) VALUES ($1, NOW(), $2)", [req.body.email, req.body.password]);
  res.sendStatus(201);
};
