// corpus: expect=PG-AUTH-001
app.post("/register", async ({ body }) => {
  const { pw } = body;
  await User.create({ password: pw });
  return { ok: true };
});
