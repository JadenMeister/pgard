// corpus: expect=PG-SQL-001
import type { Context } from "koa";
import { Pool } from "pg";
const pool = new Pool();

export async function show(ctx: Context) {
  const { id } = ctx.params;
  const result = await pool.query("SELECT * FROM invoices WHERE id = " + id);
  ctx.body = result.rows;
}
