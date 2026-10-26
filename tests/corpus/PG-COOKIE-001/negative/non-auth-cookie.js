// corpus: expect=none; known=fp:PG-COOKIE-001:any res.cookie() without flags is reported, including a non-auth theme cookie
app.get("/", (req, res) => {
  res.cookie("theme", "dark");
  res.sendStatus(204);
});
