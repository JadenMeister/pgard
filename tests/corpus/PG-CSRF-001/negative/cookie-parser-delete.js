// corpus: expect=none; known=fp:PG-CSRF-001:DELETE is not a simple cross-site method (it needs a CORS preflight), so a cookie-parser app with only a DELETE route has no realistic CSRF path
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());

app.delete("/account", (req, res) => {
  res.sendStatus(204);
});
