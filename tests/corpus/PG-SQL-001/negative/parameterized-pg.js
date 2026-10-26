// corpus: expect=none
const { Pool } = require("pg");
const pool = new Pool();

module.exports = async function find(req, res) {
  const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [req.query.email]);
  res.json(rows);
};
