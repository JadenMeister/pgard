// corpus: expect=PG-SQL-001
const { Pool } = require("pg");
const pool = new Pool();

function buildSearch(name) {
  return "SELECT * FROM products WHERE name = '" + name + "'";
}

module.exports = (req, res) => pool.query(buildSearch(req.query.name)).then((r) => res.json(r.rows));
