// corpus: expect=PG-SQL-001
import Fastify from "fastify";
import { Pool } from "pg";
const pool = new Pool();
const col = "created_at";
const app = Fastify();
app.get("/items", async (request) => {
  const { col } = request.query as any;
  const { rows } = await pool.query(`SELECT * FROM items ORDER BY ${col}`);
  return rows;
});
