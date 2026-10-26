// corpus: expect=PG-AUTH-001
module.exports = async (req, res) => {
  const { newPass } = req.body;
  await knex("users").where({ id: req.user.id }).update({ password: newPass });
  res.sendStatus(204);
};
