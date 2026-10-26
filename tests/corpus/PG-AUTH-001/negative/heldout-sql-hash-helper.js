// corpus: expect=none
const { hashSecret } = require("./secrets");

module.exports = async (req, res) => {
  const stored = await hashSecret(req.body.password);
  await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [req.body.email, stored]);
  res.sendStatus(201);
};
