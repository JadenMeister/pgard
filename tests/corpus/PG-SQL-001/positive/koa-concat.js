// corpus: expect=PG-SQL-001
import Router from "@koa/router";
import mysql from "mysql2/promise";

const router = new Router();
const pool = mysql.createPool({ host: "localhost", database: "shop" });

router.get("/orders", async (ctx) => {
  const [rows] = await pool.query("SELECT * FROM orders WHERE customer = '" + ctx.query.customer + "'");
  ctx.body = rows;
});
export default router;
