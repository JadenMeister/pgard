// corpus: expect=PG-PATH-001
const path = require("node:path");
const UPLOADS = path.resolve("uploads");

app.get("/download", (req, res) => {
  res.sendFile(path.join(UPLOADS, req.query.name));
});
