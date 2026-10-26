// corpus: expect=none; allow=low
const cp = require("node:child_process");
const NODE = process.execPath;
const SCRIPT = "scripts/build.js";

cp.exec(`${NODE} ${SCRIPT} --prod`, (err, out) => console.log(out));
