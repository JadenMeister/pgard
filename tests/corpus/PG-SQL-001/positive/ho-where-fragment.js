// corpus: expect=PG-SQL-001
const { Client } = require("pg");
const client = new Client();

async function search(req, res) {
  const where = "name = '" + req.query.name + "'";
  const result = await client.query("SELECT id, name FROM products WHERE " + where);
  res.json(result.rows);
}
module.exports = search;
