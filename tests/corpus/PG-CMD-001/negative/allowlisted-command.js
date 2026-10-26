// corpus: expect=none
const { exec } = require("node:child_process");
const ACTIONS = { restart: "systemctl restart app", status: "systemctl status app" };

app.post("/ctl", (req, res) => {
  const cmd = ACTIONS[req.body.action];
  if (!cmd) return res.sendStatus(400);
  exec(cmd, () => res.sendStatus(202));
});
