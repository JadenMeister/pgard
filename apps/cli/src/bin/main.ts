#!/usr/bin/env node
import { main } from "../app.js";

// Defence in depth on Windows: never search the current directory for executables (libuv reads
// this from the parent environment, and child processes inherit it).
process.env.NoDefaultCurrentDirectoryInExePath = "1";

const exitCode = await main(process.argv.slice(2), {
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  env: process.env,
  cwd: process.cwd(),
});
process.exitCode = exitCode;
