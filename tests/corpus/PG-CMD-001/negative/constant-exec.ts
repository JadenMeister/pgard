// corpus: expect=none
import { execSync } from "node:child_process";

export const gitSha = execSync("git rev-parse HEAD").toString().trim();
