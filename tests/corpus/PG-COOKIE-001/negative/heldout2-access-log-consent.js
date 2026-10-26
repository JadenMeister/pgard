// corpus: expect=none
module.exports = (req, res) => {
  res.cookie("access_log_consent", "yes");
  res.sendStatus(204);
};
