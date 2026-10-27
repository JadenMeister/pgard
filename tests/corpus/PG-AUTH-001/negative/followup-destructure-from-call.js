// corpus: expect=none; known=fp:PG-AUTH-001:a password-named binding destructured from a call result is treated as plain
module.exports = async (req, res) => {
  const { password } = await loadSecrets(req.user);
  await Vault.create({ owner: req.user.id, password });
  res.sendStatus(201);
};
