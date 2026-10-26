// corpus: expect=none
import { exec } from "child_process";
import shellQuote from "shell-quote";

export function log(req: any, res: any) {
  exec(`git log --oneline ${shellQuote.quote([String(req.query.ref)])}`, (err, out) => res.send(out));
}
