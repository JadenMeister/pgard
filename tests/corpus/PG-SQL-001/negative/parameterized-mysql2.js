// corpus: expect=none
import mysql from "mysql2/promise";
const pool = mysql.createPool({ host: "localhost" });

export async function byCustomer(req, res) {
  const [rows] = await pool.query("SELECT * FROM orders WHERE customer = ? AND status = ?", [
    req.query.customer,
    "open",
  ]);
  res.json(rows);
}
