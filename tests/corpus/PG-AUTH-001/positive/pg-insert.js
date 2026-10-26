// corpus: expect=PG-AUTH-001
const { Pool } = require("pg");
const pool = new Pool();

module.exports = async (req, res) => {
  await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [req.body.email, req.body.password]);
  res.sendStatus(201);
};
