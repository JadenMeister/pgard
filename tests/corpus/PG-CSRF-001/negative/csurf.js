// corpus: expect=none
const express = require("express");
const session = require("express-session");
const csurf = require("csurf");
const app = express();
app.use(session({ secret: process.env.S, resave: false, saveUninitialized: false, cookie: { httpOnly: true, secure: true, sameSite: "lax" } }));
app.use(csurf());

app.post("/transfer", (req, res) => res.json({ ok: true }));
