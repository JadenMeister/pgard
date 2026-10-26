// corpus: expect=PG-CSRF-001
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());
// Any origin is reflected and credentials are allowed, so the DELETE preflight succeeds.
app.use(cors({ origin: true, credentials: true }));

app.delete("/account", (req, res) => {
  res.sendStatus(204);
});
