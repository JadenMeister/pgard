// corpus: expect=none
const { Pool } = require("pg");
const pool = new Pool();
const SORTABLE = new Map([["new", "created_at DESC"], ["name", "name ASC"]]);

module.exports = async function list(req, res) {
  const order = SORTABLE.get(req.query.sort) ?? "created_at DESC";
  const { rows } = await pool.query("SELECT * FROM posts ORDER BY " + order);
  res.json(rows);
};
