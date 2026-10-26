// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  await db.query("UPDATE users SET password = $1 WHERE id = $2", [req.body.newPassword, req.user.id]);
  res.sendStatus(204);
};
