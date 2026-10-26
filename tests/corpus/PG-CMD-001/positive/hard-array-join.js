// corpus: expect=PG-CMD-001
const { execSync } = require("node:child_process");

module.exports = (req, res) => {
  const cmd = ["ls", "-la", req.query.dir].join(" ");
  res.send(execSync(cmd).toString());
};
