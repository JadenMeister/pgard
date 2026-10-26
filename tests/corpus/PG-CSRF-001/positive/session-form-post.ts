// corpus: expect=PG-CSRF-001,PG-COOKIE-001
import express from "express";
import session from "express-session";

const app = express();
app.use(express.urlencoded({ extended: false }));
// Default cookie options: no SameSite, so a cross-site form POST carries the session.
app.use(session({ secret: process.env.SESSION_SECRET!, resave: false, saveUninitialized: false }));

app.post("/email", (req, res) => {
  res.redirect("/settings");
});
