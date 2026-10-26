// corpus: expect=PG-CMD-001
const { exec } = require("child_process");

module.exports = (req, res) => {
  exec("convert " + req.body.file + " out.png", (err) => res.sendStatus(err ? 500 : 200));
};
