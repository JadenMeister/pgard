// corpus: expect=PG-SQL-001
const { Pool } = require("pg");
const pool = new Pool();
function defaults() {
  const sortCol = "id";
  return sortCol;
}
module.exports = async (req, res) => {
  sortCol = req.query.sort;
  res.json((await pool.query("SELECT * FROM t ORDER BY " + sortCol)).rows);
  defaults();
};
