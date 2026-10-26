// corpus: expect=none; known=fp:PG-SQL-001:a value picked from an allowlist map is still concatenated, and the analyzer does not see that it is constant
const { Pool } = require("pg");
const pool = new Pool();
const SORTABLE = new Map([["new", "created_at DESC"], ["name", "name ASC"]]);

module.exports = async function list(req, res) {
  const order = SORTABLE.get(req.query.sort) ?? "created_at DESC";
  const { rows } = await pool.query("SELECT * FROM posts ORDER BY " + order);
  res.json(rows);
};
