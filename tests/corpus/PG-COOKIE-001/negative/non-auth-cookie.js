// corpus: expect=none
app.get("/", (req, res) => {
  res.cookie("theme", "dark");
  res.sendStatus(204);
});
