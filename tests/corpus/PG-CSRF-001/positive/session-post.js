// corpus: expect=PG-CSRF-001
// Note: sameSite lax blocks cross-site POST, but same-site attackers (a sibling subdomain) remain.
const express = require("express");
const session = require("express-session");
const app = express();
app.use(session({ secret: process.env.S, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: true, sameSite: "lax" } }));

app.post("/transfer", (req, res) => {
  res.json({ ok: true });
});
