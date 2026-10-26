// corpus: expect=PG-CSRF-001
import express from "express";
const app = express();

app.put("/profile", (req, res) => {
  res.cookie("sid", "x", { httpOnly: true, secure: true, sameSite: "lax" });
  res.json({ saved: true });
});
