// corpus: expect=PG-AUTH-001; known=miss:PG-AUTH-001:mysql "SET ?" with an object of column values is not parsed
module.exports = async (req, res) => {
  await db.query("UPDATE users SET ? WHERE id = ?", [{ password: req.body.password }, req.user.id]);
  res.sendStatus(204);
};
