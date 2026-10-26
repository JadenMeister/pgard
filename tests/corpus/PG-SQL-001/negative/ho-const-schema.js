// corpus: expect=none
const { Pool } = require("pg");
const pool = new Pool();
const SCHEMA = "reporting";
const USERS = `${SCHEMA}.users`;

module.exports = async function find(req, res) {
  const text = `SELECT id, email FROM ${USERS} WHERE id = $1`;
  const { rows } = await pool.query(text, [req.params.id]);
  res.json(rows);
};
