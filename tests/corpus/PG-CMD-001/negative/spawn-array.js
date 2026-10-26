// corpus: expect=none
const { spawn } = require("node:child_process");

module.exports = (file) => spawn("convert", [file, "out.png"]);
