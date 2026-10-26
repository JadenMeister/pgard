// corpus: expect=none
const express = require("express");
const session = require("express-session");
const app = express();
app.use(session({ secret: process.env.S, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: true, sameSite: "lax" } }));

app.get("/profile", (req, res) => res.json({ ok: true }));
