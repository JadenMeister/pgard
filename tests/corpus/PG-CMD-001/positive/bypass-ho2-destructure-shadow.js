// corpus: expect=PG-CMD-001
const { execSync } = require("child_process");
const branch = "main";
module.exports = (req, res) => {
  const { branch } = req.body;
  res.send(execSync("git log --oneline " + branch).toString());
};
