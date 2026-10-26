// corpus: expect=none
import { Pool } from "pg";
const pool = new Pool();
const DIRECTIONS: Record<string, string> = { asc: "ASC", desc: "DESC" };

export async function list(req: any) {
  const dir = DIRECTIONS[String(req.query.dir).toLowerCase()] ?? "ASC";
  return pool.query("SELECT * FROM events ORDER BY ts " + dir);
}
