// corpus: expect=none; known=fp:PG-CMD-001:a template literal that interpolates only a module constant is reported as dynamic
const { exec } = require("node:child_process");
const VERSION = "1.2.3";

exec(`npm view pgard@${VERSION} version`, (err, out) => console.log(out));
