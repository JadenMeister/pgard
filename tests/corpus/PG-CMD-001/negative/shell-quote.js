// corpus: expect=none; known=fp:PG-CMD-001:a shell-quote quote() call is not recognised as escaping
const { exec } = require("node:child_process");
const { quote } = require("shell-quote");

module.exports = (req, res) => {
  exec("git log " + quote([req.query.ref]), (err, out) => res.send(out));
};
