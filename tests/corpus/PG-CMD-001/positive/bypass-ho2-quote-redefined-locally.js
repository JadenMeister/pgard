// corpus: expect=PG-CMD-001
import { exec } from "node:child_process";
import { quote } from "shell-quote";
export function list(req, res) {
  const quote = (parts) => parts.join(" ");
  exec(`ls ${quote([req.query.dir])}`, (err, out) => res.send(out));
}
