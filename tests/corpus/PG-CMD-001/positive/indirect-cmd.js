// corpus: expect=PG-CMD-001
import cp from "child_process";

export function archive(req, res) {
  const dir = req.query.dir;
  const cmd = "tar czf backup.tgz " + dir;
  cp.exec(cmd, () => res.sendStatus(200));
}
