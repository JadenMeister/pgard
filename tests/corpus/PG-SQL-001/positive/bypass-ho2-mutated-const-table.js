// corpus: expect=PG-SQL-001
const { Pool } = require("pg");
const pool = new Pool();
const COLUMNS = { name: "name", age: "age" };
module.exports = async (req, res) => {
  COLUMNS[req.query.alias] = req.query.expr;
  const { rows } = await pool.query(`SELECT id, ${COLUMNS[req.query.alias]} FROM people`);
  res.json(rows);
};
