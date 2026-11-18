// corpus: expect=PG-BRUTE-001
const express = require("express");
const authRouter = express.Router();

authRouter.post("/login", async (req, res) => {
  res.json({ ok: !!(await verify(req.body.email, req.body.password)) });
});

module.exports = authRouter;
