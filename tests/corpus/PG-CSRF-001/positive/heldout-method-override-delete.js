// corpus: expect=PG-CSRF-001
// method-override lets a cross-site form POST (?_method=DELETE) reach the DELETE route without a preflight.
const express = require("express");
const methodOverride = require("method-override");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());
app.use(methodOverride("_method"));

app.delete("/account", (req, res) => {
  res.sendStatus(204);
});
