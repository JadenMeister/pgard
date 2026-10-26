// corpus: expect=low
const mysql = require("mysql2/promise");

module.exports = async function page(req, res) {
  const conn = await mysql.createConnection(process.env.DB_URL);
  const size = Math.min(Number(req.query.size) || 25, 100);
  const [rows] = await conn.query(
    "SELECT * FROM posts LIMIT " + size + " OFFSET " + parseInt(req.query.offset, 10),
  );
  res.json(rows);
};
