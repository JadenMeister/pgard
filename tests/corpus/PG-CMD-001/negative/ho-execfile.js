// corpus: expect=none
const { execFile } = require("node:child_process");

module.exports = (req, res) => {
  execFile("git", ["log", "--oneline", "-n", "5", "--", String(req.query.path)], (err, out) => res.send(out));
};
