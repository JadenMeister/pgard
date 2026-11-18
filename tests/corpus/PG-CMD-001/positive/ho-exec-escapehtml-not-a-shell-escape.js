// corpus: expect=PG-CMD-001
import { exec } from "child_process";
import escapeHtml from "escape-html";

// escape-html does nothing about ; | $ in a shell command.
app.get("/cat", (req, res) => {
  exec("cat " + escapeHtml(req.query.file), (err, out) => res.send(out));
});
