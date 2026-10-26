// corpus: expect=none
// The password comes from a looked-up record, not from a request.
module.exports = async (req, res) => {
  await Backup.create({ password: getUser(req).password });
  res.sendStatus(201);
};
