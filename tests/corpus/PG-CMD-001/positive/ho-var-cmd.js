// corpus: expect=PG-CMD-001
const cp = require("child_process");

module.exports = (req, res) => {
  const cmd = "grep -r " + req.query.q + " ./logs";
  cp.exec(cmd, (err, out) => res.send(out));
};
