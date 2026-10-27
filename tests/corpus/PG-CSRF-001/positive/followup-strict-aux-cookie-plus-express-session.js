// corpus: expect=PG-CSRF-001
// A strict auxiliary cookie must not hide the express-session cookie session.
const express = require("express");
const app = express();
app.use(require("express-session")({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
app.post("/rotate", (req, res) => {
  res.cookie("refresh_token", mint(req.session.userId), { httpOnly: true, secure: true, sameSite: "strict" });
  res.end();
});
app.post("/transfer", (req, res) => transfer(req.session.userId, req.body).then(() => res.end()));
