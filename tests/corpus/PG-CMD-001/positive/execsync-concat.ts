// corpus: expect=PG-CMD-001
import { execSync } from "node:child_process";

export function ping(host: string) {
  return execSync("ping -c 1 " + host).toString();
}
