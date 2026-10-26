// corpus: expect=none
import express from "express";
import { RateLimiterMemory } from "rate-limiter-flexible";

const limiter = new RateLimiterMemory({ points: 5, duration: 60 });
const app = express();
app.post("/login", async (req, res) => {
  await limiter.consume(req.ip!);
  res.json({ ok: true });
});
