#!/usr/bin/env node
import { main } from "../app.js";

const exitCode = await main(process.argv.slice(2), {
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  env: process.env,
  cwd: process.cwd(),
});
process.exitCode = exitCode;
