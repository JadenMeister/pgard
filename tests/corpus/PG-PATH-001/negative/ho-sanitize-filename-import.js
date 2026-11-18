// corpus: expect=none
import path from "path";
import sanitize from "sanitize-filename";

app.get("/files/:name", (req, res) => {
  res.sendFile(path.join(__dirname, "uploads", sanitize(req.params.name)));
});
