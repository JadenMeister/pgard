// corpus: expect=none
// "tokenizerMode" is an editor preference: the word "token" is only a substring of the identifier.
module.exports = (req, res) => {
  const tokenizerMode = req.query.mode;
  res.cookie("editor_mode", tokenizerMode);
  res.sendStatus(204);
};
