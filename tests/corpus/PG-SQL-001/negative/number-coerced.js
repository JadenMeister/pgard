// corpus: expect=none; allow=low
const { Pool } = require("pg");
const pool = new Pool();

module.exports = async function page(req, res) {
  const limit = Number.parseInt(req.query.limit, 10) || 20;
  const { rows } = await pool.query(`SELECT * FROM posts LIMIT ${limit}`);
  res.json(rows);
};
