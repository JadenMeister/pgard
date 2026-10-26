// corpus: expect=none
const { Pool } = require("pg");
const pool = new Pool();
const TABLE = "audit_log";

async function recent() {
  // The only interpolated value is a module constant, not user input.
  return pool.query(`SELECT * FROM ${TABLE} ORDER BY id DESC LIMIT 50`);
}
module.exports = { recent };
