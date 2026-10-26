// corpus: expect=none
const path = require("node:path");
const UPLOADS = path.resolve("uploads");

app.get("/download", (req, res) => {
  const file = path.resolve(UPLOADS, path.basename(req.query.name));
  if (!file.startsWith(UPLOADS + path.sep)) return res.sendStatus(400);
  res.sendFile(file);
});
