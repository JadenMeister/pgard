// corpus: expect=none
const { execFile } = require("node:child_process");

app.get("/log", (req, res) => {
  execFile("git", ["log", "--oneline", "--end-of-options", req.query.ref, "--"], (err, stdout) => res.send(stdout));
});
