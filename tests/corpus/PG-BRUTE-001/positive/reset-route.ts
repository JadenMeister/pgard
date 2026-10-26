// corpus: expect=PG-BRUTE-001
import express from "express";
const app = express();

app.post("/auth/reset-password", async (req, res) => {
  await sendResetMail(req.body.email);
  res.sendStatus(202);
});
