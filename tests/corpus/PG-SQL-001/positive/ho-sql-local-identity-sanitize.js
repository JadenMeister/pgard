// corpus: expect=PG-SQL-001
import { Pool } from "pg";

const pool = new Pool();
function sanitize(value) {
  return value;
}

app.get("/user", async (req, res) => {
  const result = await pool.query(`SELECT * FROM users WHERE id = ${sanitize(req.query.id)}`);
  res.json(result.rows);
});
