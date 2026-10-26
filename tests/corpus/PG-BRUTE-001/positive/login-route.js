// corpus: expect=PG-BRUTE-001
const express = require("express");
const app = express();

app.post("/login", async (req, res) => {
  const user = await verify(req.body.email, req.body.password);
  res.json({ ok: !!user });
});
