// corpus: expect=none
import { Pool } from "pg";
const pool = new Pool();

export async function countUsers() {
  const { rows } = await pool.query("SELECT count(*) FROM users");
  return rows[0].count;
}
