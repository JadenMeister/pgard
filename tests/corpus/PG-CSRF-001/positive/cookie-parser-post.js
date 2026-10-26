// corpus: expect=PG-CSRF-001
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());

app.post("/transfer", (req, res) => {
  const user = lookup(req.cookies.sid);
  res.json({ from: user.id });
});
