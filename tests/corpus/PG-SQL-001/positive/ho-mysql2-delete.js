// corpus: expect=PG-SQL-001
const mysql = require("mysql2/promise");

module.exports = async function removeSessions(req, res) {
  const conn = await mysql.createConnection(process.env.DB_URL);
  await conn.execute(`DELETE FROM sessions WHERE owner = '${req.body.user}'`);
  res.sendStatus(204);
};
