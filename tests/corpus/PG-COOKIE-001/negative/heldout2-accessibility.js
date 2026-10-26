// corpus: expect=none
module.exports = (req, res) => {
  res.cookie("accessibility", "high-contrast", { path: "/" });
  res.sendStatus(204);
};
