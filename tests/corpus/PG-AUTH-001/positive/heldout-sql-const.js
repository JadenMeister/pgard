// corpus: expect=PG-AUTH-001
const INSERT_USER = "INSERT INTO users (email, password) VALUES ($1, $2)";

module.exports = async (req, res) => {
  await pool.query(INSERT_USER, [req.body.email, req.body.password]);
  res.sendStatus(201);
};
