// corpus: expect=none
const FEEDS = { news: "https://feeds.example.com/news.xml", blog: "https://feeds.example.com/blog.xml" };

app.get("/feed", async (req, res) => {
  const feed = FEEDS[req.query.id];
  if (!feed) return res.sendStatus(404);
  res.send(await (await fetch(feed)).text());
});
