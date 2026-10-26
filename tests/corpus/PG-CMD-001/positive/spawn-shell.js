// corpus: expect=PG-CMD-001
const { spawn } = require("node:child_process");

module.exports = (req, res) => {
  const child = spawn("convert " + req.body.file + " out.png", { shell: true });
  child.on("close", () => res.end("done"));
};
