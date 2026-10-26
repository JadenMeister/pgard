// corpus: expect=PG-SQL-001
// The sort column is allowlisted, but the search term is concatenated unescaped.
const { Pool } = require("pg");
const pool = new Pool();
const SORTABLE = new Map([["new", "created_at DESC"], ["name", "name ASC"]]);

module.exports = async function list(req, res) {
  const order = SORTABLE.get(req.query.sort) ?? "created_at DESC";
  const { rows } = await pool.query(
    "SELECT * FROM posts WHERE title LIKE '%" + req.query.q + "%' ORDER BY " + order,
  );
  res.json(rows);
};
