// corpus: expect=PG-CMD-001
const { exec } = require("child_process");
// A local helper called quote is not the shell-quote package and may not escape anything.
const { quote } = require("./text-utils");

module.exports = (req, res) => {
  exec("git log " + quote(req.query.ref), (err, out) => res.send(out));
};
