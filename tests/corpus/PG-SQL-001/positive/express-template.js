// corpus: expect=PG-SQL-001
const express = require("express");
const { Pool } = require("pg");
const pool = new Pool();
const app = express();

app.get("/users", async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM users WHERE email = '${req.query.email}'`);
  res.json(rows);
});
