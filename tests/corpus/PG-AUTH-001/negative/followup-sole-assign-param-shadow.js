// corpus: expect=none
const bcrypt = require("bcrypt");
async function login(req, res) {
  let pw;
  pw = req.body.password;
  res.json({ ok: await check(req.body.email, pw) });
}
async function persist(user, pw) {
  user.password = pw;
  await user.save();
}
async function signup(req, res) {
  const user = new User({ email: req.body.email });
  await persist(user, await bcrypt.hash(req.body.password, 12));
  res.sendStatus(201);
}
module.exports = { login, signup, persist };
