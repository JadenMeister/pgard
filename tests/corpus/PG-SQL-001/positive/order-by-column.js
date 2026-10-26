// corpus: expect=PG-SQL-001
const { Pool } = require("pg");
const pool = new Pool();

module.exports = async function list(req, res) {
  const sort = req.query.sort;
  const { rows } = await pool.query(`SELECT * FROM posts ORDER BY ${sort}`);
  res.json(rows);
};
