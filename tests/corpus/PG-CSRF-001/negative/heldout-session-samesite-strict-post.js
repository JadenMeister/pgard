// corpus: expect=none
// SameSite=Strict keeps the session cookie off every cross-site request, so a forged POST is unauthenticated.
const express = require("express");
const session = require("express-session");
const app = express();
app.use(session({ secret: process.env.S, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: true, sameSite: "strict" } }));

app.post("/transfer", (req, res) => res.json({ ok: true }));
