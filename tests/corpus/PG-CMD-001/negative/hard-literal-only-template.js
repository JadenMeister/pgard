// corpus: expect=none
const { exec } = require("node:child_process");
const VERSION = "1.2.3";

exec(`npm view pgard@${VERSION} version`, (err, out) => console.log(out));
