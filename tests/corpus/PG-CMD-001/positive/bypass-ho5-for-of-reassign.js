// corpus: expect=PG-CMD-001
const { execSync } = require("child_process");
module.exports = (req, res) => {
  let pkg = "lodash";
  for (pkg of [].concat(req.query.pkgs || [])) execSync("npm view " + pkg + " version");
  res.end();
};
