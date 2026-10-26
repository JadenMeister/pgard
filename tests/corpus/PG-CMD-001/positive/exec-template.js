// corpus: expect=PG-CMD-001
const { exec } = require("node:child_process");

app.get("/log", (req, res) => {
  exec(`git log --oneline ${req.query.ref}`, (err, stdout) => res.send(stdout));
});
