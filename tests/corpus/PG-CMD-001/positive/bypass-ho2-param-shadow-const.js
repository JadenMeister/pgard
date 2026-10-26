// corpus: expect=PG-CMD-001
const { exec } = require("child_process");
const target = "/var/log";
function du(target) {
  exec("du -sh " + target, () => {});
}
module.exports = (req, res) => {
  du(req.query.path);
  res.end(target);
};
