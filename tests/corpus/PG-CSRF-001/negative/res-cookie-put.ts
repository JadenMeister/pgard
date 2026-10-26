// corpus: expect=none; known=fp:PG-CSRF-001:a PUT route that only sets a cookie, with no cookie session, and a cross-site PUT also needs a CORS preflight
import express from "express";
const app = express();

app.put("/profile", (req, res) => {
  res.cookie("sid", "x", { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ saved: true });
});
