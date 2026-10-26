// corpus: expect=PG-SQL-001
const { Pool } = require("pg");
const pool = new Pool();

module.exports = async (req, res) => {
  const clauses = ["SELECT * FROM users WHERE 1=1"];
  if (req.query.name) clauses.push("AND name = '" + req.query.name + "'");
  const { rows } = await pool.query(clauses.join(" "));
  res.json(rows);
};
