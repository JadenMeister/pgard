// corpus: expect=PG-CSRF-001
// Hand-written CORS headers reflect any origin and allow credentials, so a PATCH preflight succeeds.
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

app.patch("/profile", (req, res) => {
  res.sendStatus(204);
});
