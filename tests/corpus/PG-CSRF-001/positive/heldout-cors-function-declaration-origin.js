// corpus: expect=PG-CSRF-001
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());

function checkOrigin(origin, done) {
  done(null, true);
}
app.use(cors({ origin: checkOrigin, credentials: true }));

app.delete("/account", (req, res) => {
  res.sendStatus(204);
});
