// corpus: expect=PG-SQL-001
const { Pool } = require("pg");
const pool = new Pool();
module.exports = async (req, res) => {
  let col = "name";
  const out = [];
  for (col of [].concat(req.query.cols || [])) {
    out.push((await pool.query(`SELECT ${col} FROM users`)).rows);
  }
  res.json(out);
};
