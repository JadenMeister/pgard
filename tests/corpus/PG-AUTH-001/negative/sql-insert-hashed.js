// corpus: expect=none
const bcrypt = require("bcrypt");

module.exports = async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 12);
  await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [req.body.email, hash]);
  res.sendStatus(201);
};
