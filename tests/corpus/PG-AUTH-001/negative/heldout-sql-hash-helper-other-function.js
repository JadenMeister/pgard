// corpus: expect=none
const crypto = require("crypto");

function makeDigest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

module.exports = async (req, res) => {
  await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [req.body.email, makeDigest(req.body.password)]);
  res.sendStatus(201);
};
