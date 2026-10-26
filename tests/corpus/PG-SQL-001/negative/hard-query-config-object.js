// corpus: expect=none
const { Pool } = require("pg");
const pool = new Pool();

module.exports = (req, res) =>
  pool.query({ text: "SELECT * FROM users WHERE email = $1", values: [req.query.email] }).then((r) => res.json(r.rows));
