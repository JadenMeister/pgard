// corpus: expect=PG-CMD-001
const { exec } = require("child_process");
function setup() {
  const logDir = "/var/log/app";
  return logDir;
}
module.exports = (req, res) => {
  logDir = req.query.dir;
  exec("du -sh " + logDir, () => res.end());
  setup();
};
