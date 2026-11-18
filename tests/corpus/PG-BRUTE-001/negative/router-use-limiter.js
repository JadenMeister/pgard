// corpus: expect=none
const express = require("express");
const rateLimit = require("express-rate-limit");
const authRouter = express.Router();
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

authRouter.use(limiter);
authRouter.post("/login", async (req, res) => {
  res.json({ ok: !!(await verify(req.body.email, req.body.password)) });
});

module.exports = authRouter;
