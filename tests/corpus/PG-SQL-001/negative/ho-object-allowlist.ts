// corpus: expect=none; allow=low
import { Pool } from "pg";
const pool = new Pool();
const COLUMNS = { newest: "created_at", title: "title" } as const;

export async function list(req: any, res: any) {
  const column = COLUMNS[req.query.sort as keyof typeof COLUMNS] || "created_at";
  const { rows } = await pool.query(`SELECT * FROM posts ORDER BY ${column} DESC`);
  res.json(rows);
}
