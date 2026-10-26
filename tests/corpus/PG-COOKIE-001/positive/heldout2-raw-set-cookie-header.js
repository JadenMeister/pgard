// corpus: expect=PG-COOKIE-001; known=miss:PG-COOKIE-001:a raw Set-Cookie header string is not parsed
app.get("/cb", (req, res) => {
  res.setHeader("Set-Cookie", "session=" + issue(req) + "; Path=/");
  res.sendStatus(204);
});
