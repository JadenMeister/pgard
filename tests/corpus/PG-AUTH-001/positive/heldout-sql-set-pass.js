// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  await db.query("UPDATE users SET pass = $1 WHERE id = $2", [req.body.password, req.user.id]);
  res.sendStatus(204);
};
