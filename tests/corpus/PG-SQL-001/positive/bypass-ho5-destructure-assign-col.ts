// corpus: expect=PG-SQL-001
import { Pool } from "pg";
const pool = new Pool();
export async function list(req: any, res: any) {
  let order = "id";
  ({ order } = req.query);
  const { rows } = await pool.query(`SELECT * FROM t ORDER BY ${order}`);
  res.json(rows);
}
