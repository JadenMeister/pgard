// corpus: expect=PG-SQL-001
const mysql = require("mysql2/promise");
const db = mysql.createPool({});
const table = "users";
async function listFrom(table) {
  return db.query("SELECT * FROM " + table);
}
module.exports = async (req, res) => {
  res.json(await listFrom(req.query.t));
  console.log(table);
};
