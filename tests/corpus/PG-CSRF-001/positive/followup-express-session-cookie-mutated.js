// corpus: expect=PG-CSRF-001,PG-COOKIE-001
const express = require("express");
const app = express();
const session = require("express-session");
const cookie = { httpOnly: true, secure: true, sameSite: "strict" };
if (process.env.EMBED) cookie.sameSite = "none";
app.use(session({ secret: process.env.S, resave: false, saveUninitialized: false, cookie }));
app.post("/transfer", (req, res) => res.end());
