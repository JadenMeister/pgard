// corpus: expect=PG-SQL-001
import { Pool } from "pg";
const pool = new Pool();

export async function findByName(req: { body: { name: string } }) {
  const name = req.body.name;
  const sql = `SELECT id, name FROM products WHERE name LIKE '%${name}%'`;
  return pool.query(sql);
}
