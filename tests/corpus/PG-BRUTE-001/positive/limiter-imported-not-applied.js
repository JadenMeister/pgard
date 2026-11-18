// corpus: expect=PG-BRUTE-001
const express = require("express");
const rateLimit = require("express-rate-limit");
const app = express();
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.use("/static", limiter);
app.post("/login", async (req, res) => {
  res.json({ ok: !!(await verify(req.body.email, req.body.password)) });
});
